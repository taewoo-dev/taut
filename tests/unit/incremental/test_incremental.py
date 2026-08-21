import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from taut.analysis.contracts import (
    AnalysisRequest,
    LanguageSettings,
    ProjectRoot,
    ResolverSettings,
    SourceInput,
)
from taut.analysis.project_analyzer import ProjectAnalyzer
from taut.analysis.python.language_adapter import PythonAstAdapter
from taut.domain.facts import SourceKind
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId
from taut.domain.location import ProjectPath
from taut.incremental import ChangeSet, IncrementalProjectAnalyzer


def _request(value: str) -> AnalysisRequest:
    source = SourceInput(
        ProjectPath("app/a.py"),
        ModuleId("app.a"),
        SourceKind.FIRST_PARTY,
        True,
        False,
        value,
        hashlib.sha256(value.encode()).hexdigest(),
    )
    adapter = PythonAstAdapter()
    return AnalysisRequest(
        ProjectRoot(Path.cwd()),
        (source,),
        LanguageSettings(),
        ResolverSettings(),
        FrozenMap(((adapter.identity.name, adapter.identity.version),)),
    )


def test_incremental_matches_fresh_and_reuses_unchanged_module() -> None:
    analyzer = IncrementalProjectAnalyzer(PythonAstAdapter())
    first = analyzer.analyze(_request("value = 1"))
    second = analyzer.analyze(_request("value = 1"))
    assert first.id == second.id
    assert analyzer.reparsed_modules == 0


def test_changeset_classifies_content_changes() -> None:
    old = _request("value = 1").sources
    new = _request("value = 2").sources
    changes = ChangeSet.compare(old, new)
    assert changes.changed == frozenset({ModuleId("app.a")})
    assert changes.touched == frozenset({ModuleId("app.a")})


def _request_many(
    values: dict[str, str], *, root: Path | None = None, language: LanguageSettings | None = None
) -> AnalysisRequest:
    adapter = PythonAstAdapter()
    sources = tuple(
        SourceInput(
            ProjectPath(path),
            ModuleId(path[:-3].replace("/", ".")),
            SourceKind.FIRST_PARTY,
            True,
            False,
            text,
            hashlib.sha256(text.encode()).hexdigest(),
        )
        for path, text in sorted(values.items())
    )
    return AnalysisRequest(
        ProjectRoot(root or Path.cwd()),
        sources,
        language or LanguageSettings(),
        ResolverSettings(),
        FrozenMap(((adapter.identity.name, adapter.identity.version),)),
    )


def test_two_module_edit_reparses_one_and_matches_fresh_snapshot() -> None:
    values = {"app/a.py": "value = 1", "app/b.py": "value = 2"}
    analyzer = IncrementalProjectAnalyzer(PythonAstAdapter())
    analyzer.analyze(_request_many(values))
    updated = dict(values)
    updated["app/a.py"] = "value = 3"
    actual = analyzer.analyze(_request_many(updated))
    expected = ProjectAnalyzer(PythonAstAdapter()).analyze(_request_many(updated))
    assert actual == expected
    assert analyzer.reparsed_modules == 1
    assert analyzer.last_changes.touched == frozenset({ModuleId("app.a")})


def test_add_remove_rename_and_empty_are_deterministic() -> None:
    analyzer = IncrementalProjectAnalyzer(PythonAstAdapter())
    first = analyzer.analyze(_request_many({"app/a.py": "value = 1", "app/b.py": "value = 2"}))
    added = analyzer.analyze(
        _request_many({"app/a.py": "value = 1", "app/b.py": "value = 2", "app/c.py": "value = 3"})
    )
    assert added == ProjectAnalyzer(PythonAstAdapter()).analyze(
        _request_many({"app/a.py": "value = 1", "app/b.py": "value = 2", "app/c.py": "value = 3"})
    )
    removed = analyzer.analyze(_request_many({"app/a.py": "value = 1"}))
    assert removed == ProjectAnalyzer(PythonAstAdapter()).analyze(
        _request_many({"app/a.py": "value = 1"})
    )
    empty = analyzer.analyze(_request_many({}))
    assert empty.modules == {} and analyzer.last_changes.removed
    assert first.modules


def test_identity_changes_reparse_all_and_record_impact() -> None:
    analyzer = IncrementalProjectAnalyzer(PythonAstAdapter())
    request = _request_many({"app/a.py": "value = 1", "app/b.py": "value = 2"})
    analyzer.analyze(request)
    changed = _request_many(
        dict((s.path.value, s.content) for s in request.sources),
        root=Path("/tmp").resolve(),
        language=LanguageSettings(target_version="3.11"),
    )
    analyzer.analyze(changed)
    assert analyzer.reparsed_modules == 2
    assert analyzer.last_impact.impacted == frozenset({ModuleId("app.a"), ModuleId("app.b")})


def test_assemble_rejects_malformed_results() -> None:
    request = _request("value = 1")
    with pytest.raises(ValueError, match="count"):
        ProjectAnalyzer.assemble(request, ())
    wrong = PythonAstAdapter().analyze_module(_request_many({"app/b.py": "value = 2"}).sources[0])
    with pytest.raises(ValueError, match="module order"):
        ProjectAnalyzer.assemble(request, (wrong,))


def test_import_impact_uses_old_and_new_graph_transitively() -> None:
    base = _request_many(
        {
            "app/a.py": "value=1",
            "app/b.py": "from app.a import value",
            "app/c.py": "from app.b import value",
        }
    )
    changed = _request_many(
        {
            "app/a.py": "value=1",
            "app/b.py": "from app.c import value",
            "app/c.py": "from app.b import value",
        }
    )
    analyzer = IncrementalProjectAnalyzer(PythonAstAdapter())
    analyzer.analyze(base)
    analyzer.analyze(changed)
    assert {ModuleId("app.b"), ModuleId("app.c")} <= analyzer.last_impact.impacted
    assert analyzer.reparsed_modules == 1


def test_syntax_failure_then_recovery_matches_fresh() -> None:
    analyzer = IncrementalProjectAnalyzer(PythonAstAdapter())
    base = _request_many({"app/a.py": "value=1"})
    analyzer.analyze(base)
    broken = _request_many({"app/a.py": "def broken("})
    failed = analyzer.analyze(broken)
    recovered = _request_many({"app/a.py": "value=2"})
    actual = analyzer.analyze(recovered)
    assert actual == ProjectAnalyzer(PythonAstAdapter()).analyze(recovered)
    assert failed.issues and actual.issues == ()


def test_source_metadata_and_module_rename_changeset() -> None:
    old = _request_many({"app/a.py": "value=1"}).sources[0]
    metadata = replace(
        old,
        path=ProjectPath("app/renamed.py"),
        module_id=ModuleId("app.renamed"),
        kind=SourceKind.THIRD_PARTY,
        is_policy_target=False,
        is_package=True,
    )
    changes = ChangeSet.compare((old,), (metadata,))
    assert changes.added == {ModuleId("app.renamed")} and changes.removed == {ModuleId("app.a")}


@pytest.mark.parametrize("dimension", ["resolver", "language", "adapter_versions", "project_root"])
def test_identity_dimension_fallbacks(dimension: str) -> None:
    analyzer = IncrementalProjectAnalyzer(PythonAstAdapter())
    request = _request_many({"app/a.py": "value=1", "app/b.py": "value=2"})
    analyzer.analyze(request)
    changed = request
    if dimension == "resolver":
        changed = replace(request, resolver=ResolverSettings(source_roots=(ProjectPath("src"),)))
    elif dimension == "language":
        changed = replace(request, language=LanguageSettings(target_version="3.11"))
    elif dimension == "adapter_versions":
        changed = replace(request, adapter_versions=FrozenMap((("python", "changed"),)))
    else:
        changed = replace(request, project_root=ProjectRoot(Path("/tmp").resolve()))
    analyzer.analyze(changed)
    assert analyzer.reparsed_modules == 2 and analyzer.last_impact.impacted == {
        ModuleId("app.a"),
        ModuleId("app.b"),
    }


def test_no_change_full_snapshot_parity_and_zero_reparse() -> None:
    request = _request_many({"app/a.py": "value=1"})
    analyzer = IncrementalProjectAnalyzer(PythonAstAdapter())
    analyzer.analyze(request)
    actual = analyzer.analyze(request)
    assert (
        actual == ProjectAnalyzer(PythonAstAdapter()).analyze(request)
        and analyzer.reparsed_modules == 0
    )


def test_cumulative_reparse_counters() -> None:
    analyzer = IncrementalProjectAnalyzer(PythonAstAdapter())
    request = _request_many({"app/a.py": "value=1"})
    analyzer.analyze(request)
    analyzer.analyze(_request_many({"app/a.py": "value=2"}))
    assert analyzer.total_reparsed_modules == 2 and analyzer.reparsed_modules == 1


def test_add_remove_each_matches_fresh_and_exact_counts() -> None:
    analyzer = IncrementalProjectAnalyzer(PythonAstAdapter())
    analyzer.analyze(_request_many({"app/a.py": "value=1"}))
    added = _request_many({"app/a.py": "value=1", "app/b.py": "value=2"})
    assert analyzer.analyze(added) == ProjectAnalyzer(PythonAstAdapter()).analyze(added)
    assert analyzer.reparsed_modules == 1
    removed = _request_many({"app/a.py": "value=1"})
    assert analyzer.analyze(removed) == ProjectAnalyzer(PythonAstAdapter()).analyze(removed)
    assert analyzer.reparsed_modules == 0
