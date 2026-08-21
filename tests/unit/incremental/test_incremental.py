import hashlib
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
