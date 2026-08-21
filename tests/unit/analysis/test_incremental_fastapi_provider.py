from __future__ import annotations

from tests.utils.builders import analyze, make_source

from taut.analysis.framework.fastapi import FastAPIProvider
from taut.domain.ids import ModuleId
from taut.domain.snapshot import AnalysisSnapshot


def _snapshot(text: str = "value = 1") -> AnalysisSnapshot:
    return analyze(make_source("app/a.py", text))


class SpyFastAPIProvider(FastAPIProvider):
    def analyze(self, snapshot):  # type: ignore[no-untyped-def]
        raise AssertionError("incremental path called full analyze")


def test_spy_incremental_does_not_invoke_full_analyze() -> None:
    snapshot = _snapshot()
    provider = SpyFastAPIProvider()
    previous = FastAPIProvider().analyze(snapshot)
    result = provider.analyze_incremental(snapshot, previous, frozenset({ModuleId("app.a")}))
    assert result == provider.analyze_incremental(snapshot, previous, frozenset())


def test_module_visit_selection_is_empty_for_empty_impact() -> None:
    snapshot = _snapshot()
    provider = FastAPIProvider()
    previous = provider.analyze(snapshot)
    assert provider.analyze_incremental(snapshot, previous, frozenset()) == previous


def test_endpoint_edit_incremental_parity() -> None:
    old = _snapshot("value = 1")
    new = _snapshot("value = 2")
    provider = FastAPIProvider()
    assert provider.analyze_incremental(
        new, provider.analyze(old), frozenset({ModuleId("app.a")})
    ) == provider.analyze(new)


def test_router_and_dependent_module_parity() -> None:
    snapshot = _snapshot("from fastapi import APIRouter\nr = APIRouter()")
    provider = FastAPIProvider()
    full = provider.analyze(snapshot)
    assert provider.analyze_incremental(snapshot, full, frozenset({ModuleId("app.a")})) == full


def test_add_remove_capability_parity() -> None:
    snapshot = _snapshot()
    provider = FastAPIProvider()
    full = provider.analyze(snapshot)
    assert provider.analyze_incremental(snapshot, full, frozenset({ModuleId("app.a")})) == full


def test_empty_snapshot_incremental_values_are_stable() -> None:
    snapshot = _snapshot()
    provider = FastAPIProvider()
    values = provider.analyze(snapshot)
    assert provider.analyze_incremental(snapshot, values, frozenset()) == values
