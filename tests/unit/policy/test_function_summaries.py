from __future__ import annotations

from dataclasses import replace

from tests.utils.builders import analyze, make_context, make_source

from taut.configuration.catalog import AccessPath, CatalogEntry, Effect
from taut.domain.ids import ModuleId, SymbolId
from taut.policy.context import PolicyContext
from taut.policy.function_summaries import strongly_connected_components


def test_recursive_component_shares_transitive_effects() -> None:
    snapshot = analyze(
        make_source("vendor.py", "def send(): pass\n"),
        make_source(
            "app/service.py",
            """from vendor import send

def first():
    second()

def second():
    first()
    send()
""",
        ),
    )
    context = make_context(
        snapshot,
        roles={"service": ("app/**", "vendor.py")},
        extra_catalog_entries=(
            CatalogEntry(
                SymbolId("vendor.send"),
                frozenset({Effect.EXTERNAL_CALL}),
                AccessPath.DIRECT,
            ),
        ),
    )

    first = context.function_summary(SymbolId("app.service.first"))
    second = context.function_summary(SymbolId("app.service.second"))

    assert first is not None and first.effects == frozenset({Effect.EXTERNAL_CALL})
    assert second is not None and second.effects == frozenset({Effect.EXTERNAL_CALL})


def test_component_discovery_is_deterministic_for_cycles() -> None:
    first = SymbolId("app.first")
    second = SymbolId("app.second")
    leaf = SymbolId("app.leaf")
    graph: dict[SymbolId, frozenset[SymbolId]] = {
        second: frozenset({first, leaf}),
        leaf: frozenset(),
        first: frozenset({second}),
    }

    assert strongly_connected_components(graph) == (
        (first, second),
        (leaf,),
    )


def test_component_discovery_handles_deep_call_chains_without_recursion() -> None:
    symbols = tuple(SymbolId(f"app.function_{index:04}") for index in range(2_000))
    graph: dict[SymbolId, frozenset[SymbolId]] = {
        symbol: (
            frozenset({symbols[index + 1]}) if index + 1 < len(symbols) else frozenset[SymbolId]()
        )
        for index, symbol in enumerate(symbols)
    }

    components = strongly_connected_components(graph)

    assert len(components) == len(symbols)
    assert all(len(component) == 1 for component in components)


def test_incremental_state_reuses_unaffected_direct_summaries() -> None:
    catalog_entry = CatalogEntry(
        SymbolId("vendor.send"),
        frozenset({Effect.EXTERNAL_CALL}),
        AccessPath.DIRECT,
    )

    def context_for(value: int) -> PolicyContext:
        return make_context(
            analyze(
                make_source("vendor.py", "def send(): pass\n"),
                make_source(
                    "app/changed.py",
                    f"from vendor import send\ndef changed():\n    send()\n    return {value}\n",
                ),
                make_source(
                    "app/stable.py",
                    "from vendor import send\ndef stable():\n    send()\n",
                ),
            ),
            roles={"service": ("app/**", "vendor.py")},
            extra_catalog_entries=(catalog_entry,),
        )

    old = context_for(1)
    prior = old.function_summary_state
    fresh = context_for(2)
    incremental = replace(
        fresh,
        prior_function_summary_state=prior,
        function_summary_invalidated_modules=frozenset({ModuleId("app.changed")}),
    )

    state = incremental.function_summary_state

    assert state.summaries == fresh.function_summary_state.summaries
    assert (
        state.direct[SymbolId("app.stable.stable")] is prior.direct[SymbolId("app.stable.stable")]
    )
    assert (
        state.summaries[SymbolId("app.stable.stable")]
        is prior.summaries[SymbolId("app.stable.stable")]
    )
    assert state.reused_functions == 2
    assert state.recomputed_functions == 1
    assert state.evaluated_calls == 1
    assert state.reused_components == 3
    assert state.recomputed_components == 0


def test_incremental_effect_change_propagates_to_callers() -> None:
    catalog_entry = CatalogEntry(
        SymbolId("vendor.send"),
        frozenset({Effect.EXTERNAL_CALL}),
        AccessPath.DIRECT,
    )

    def context_for(send: bool) -> PolicyContext:
        body = "    send()\n" if send else "    return None\n"
        return make_context(
            analyze(
                make_source("vendor.py", "def send(): pass\n"),
                make_source(
                    "app/callee.py",
                    f"from vendor import send\ndef callee():\n{body}",
                ),
                make_source(
                    "app/caller.py",
                    "from app.callee import callee\ndef caller():\n    callee()\n",
                ),
            ),
            roles={"service": ("app/**", "vendor.py")},
            extra_catalog_entries=(catalog_entry,),
        )

    old = context_for(False)
    fresh = context_for(True)
    incremental = replace(
        fresh,
        prior_function_summary_state=old.function_summary_state,
        function_summary_invalidated_modules=frozenset({ModuleId("app.callee")}),
    )

    state = incremental.function_summary_state

    assert state.summaries == fresh.function_summary_state.summaries
    assert state.summaries[SymbolId("app.caller.caller")].effects == frozenset(
        {Effect.EXTERNAL_CALL}
    )
    assert state.reused_components == 1
    assert state.recomputed_components == 2
