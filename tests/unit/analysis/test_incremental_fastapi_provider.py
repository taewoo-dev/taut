from __future__ import annotations

from tests.utils.builders import analyze, make_source

from taut.analysis.contracts import SourceInput
from taut.analysis.framework.fastapi import FASTAPI_ENDPOINTS, FASTAPI_ROUTERS, FastAPIProvider
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId


def _api(path: str = "/items") -> SourceInput:
    return make_source(
        "app/api.py",
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
        "def dependency(): return 1\n"
        f"@router.get({path!r})\n"
        "def endpoint(value: int = Depends(dependency)): return value\n",
    )


class SpyFastAPIProvider(FastAPIProvider):
    def analyze(self, snapshot):  # type: ignore[no-untyped-def]
        raise AssertionError("incremental path called full analyze")


def test_spy_incremental_does_not_invoke_full_analyze() -> None:
    snapshot = analyze(_api())
    previous = FastAPIProvider().analyze(snapshot)
    result = SpyFastAPIProvider().analyze_incremental(
        snapshot, previous, frozenset({ModuleId("app.api")})
    )
    assert result == previous
    assert result[FASTAPI_ENDPOINTS]


def test_empty_impact_reuses_nonempty_capabilities_exactly() -> None:
    snapshot = analyze(_api())
    provider = FastAPIProvider()
    previous = provider.analyze(snapshot)
    assert previous[FASTAPI_ENDPOINTS]
    result = provider.analyze_incremental(snapshot, previous, frozenset())
    assert result == previous
    assert all(result[name] is previous[name] for name in previous)


def test_endpoint_edit_matches_fresh_nonempty_output() -> None:
    old = analyze(_api("/old"))
    new = analyze(_api("/new"))
    provider = FastAPIProvider()
    incremental = provider.analyze_incremental(
        new, provider.analyze(old), frozenset({ModuleId("app.api")})
    )
    full = provider.analyze(new)
    assert incremental == full
    assert incremental[FASTAPI_ENDPOINTS]
    assert incremental[FASTAPI_ENDPOINTS] != provider.analyze(old)[FASTAPI_ENDPOINTS]


def test_router_edit_with_dependent_module_matches_fresh_output() -> None:
    routes_old = make_source(
        "app/routes.py", "from fastapi import APIRouter\nrouter = APIRouter()\n"
    )
    routes_new = make_source(
        "app/routes.py", "from fastapi import APIRouter\nrouter = APIRouter()\n# changed\n"
    )
    api = make_source(
        "app/api.py",
        "from app.routes import router\n@router.get('/items')\ndef endpoint(): return 1\n",
    )
    old = analyze(routes_old, api)
    new = analyze(routes_new, api)
    provider = FastAPIProvider()
    result = provider.analyze_incremental(
        new,
        provider.analyze(old),
        frozenset({ModuleId("app.routes"), ModuleId("app.api")}),
    )
    assert result == provider.analyze(new)
    assert result[FASTAPI_ROUTERS] and result[FASTAPI_ENDPOINTS]


def test_added_module_matches_fresh_and_preserves_unaffected_facts() -> None:
    first = _api("/first")
    second = make_source(
        "app/second.py",
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/second')\n"
        "def second(): return 2\n",
    )
    old = analyze(first)
    new = analyze(first, second)
    provider = FastAPIProvider()
    previous = provider.analyze(old)
    result = provider.analyze_incremental(new, previous, frozenset({ModuleId("app.second")}))
    assert result == provider.analyze(new)
    assert len(result[FASTAPI_ENDPOINTS]) == 2


def test_removed_module_drops_only_removed_facts_and_matches_fresh() -> None:
    first = _api("/first")
    second = make_source(
        "app/second.py",
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/second')\n"
        "def second(): return 2\n",
    )
    old = analyze(first, second)
    new = analyze(first)
    provider = FastAPIProvider()
    result = provider.analyze_incremental(
        new, provider.analyze(old), frozenset({ModuleId("app.second")})
    )
    assert result == provider.analyze(new)
    assert len(result[FASTAPI_ENDPOINTS]) == 1


def test_missing_previous_values_is_a_valid_empty_incremental_seed() -> None:
    snapshot = analyze(make_source("app/plain.py", "value = 1"))
    result = FastAPIProvider().analyze_incremental(
        snapshot, FrozenMap(), frozenset({ModuleId("app.plain")})
    )
    assert result == FastAPIProvider().analyze(snapshot)
