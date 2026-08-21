import hashlib
from pathlib import Path

from taut.analysis.contracts import (
    AnalysisRequest,
    LanguageSettings,
    ProjectRoot,
    ResolverSettings,
    SourceInput,
)
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
