from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from taut.analysis.semantic_model import SemanticModel
from taut.configuration.catalog import AccessPath, Effect, EffectResolution, EffectResolutionState
from taut.configuration.effective_policy import EffectivePolicy
from taut.domain.facts import CallFact, ResolutionState
from taut.domain.frozen import FrozenMap
from taut.domain.ids import SymbolId


@dataclass(frozen=True)
class FunctionSemanticSummary:
    """Project-owned function behavior derived from its reachable call graph."""

    effect_access: FrozenMap[Effect, AccessPath] = field(
        default_factory=lambda: FrozenMap[Effect, AccessPath]()
    )
    session_providers: frozenset[SymbolId] = frozenset()
    bulk_mapping_operations: frozenset[str] = frozenset()

    @property
    def effects(self) -> frozenset[Effect]:
        return frozenset(self.effect_access)


class FunctionSummaryContext(Protocol):
    @property
    def model(self) -> SemanticModel: ...

    @property
    def policy(self) -> EffectivePolicy: ...

    def effect_of(self, call: CallFact) -> EffectResolution: ...

    def matching_symbol(
        self, symbol: SymbolId | None, candidates: frozenset[SymbolId]
    ) -> SymbolId | None: ...


def build_function_semantic_summaries(
    context: FunctionSummaryContext,
) -> FrozenMap[SymbolId, FunctionSemanticSummary]:
    """Compute deterministic transitive summaries without changing source facts.

    The context is intentionally structural here to avoid a runtime import cycle with
    ``PolicyContext``.  Its required surface is covered by policy-context tests.
    """
    model = context.model
    functions = {
        model.canonical_symbol(function.symbol_id): function
        for module_id in model.modules()
        for function in model.module(module_id).functions
    }
    calls = {
        symbol: tuple(
            call
            for call in model.calls_in(function.module_id)
            if call.enclosing_symbol == function.symbol_id
        )
        for symbol, function in functions.items()
    }
    summaries = {symbol: FunctionSemanticSummary() for symbol in functions}

    for _ in range(len(functions) + 1):
        changed = False
        for symbol in sorted(functions):
            effect_access: dict[Effect, AccessPath] = {}
            providers: set[SymbolId] = set()
            bulk_operations: set[str] = set()
            for call in calls[symbol]:
                resolution = context.effect_of(call)
                if resolution.state is EffectResolutionState.MATCHED:
                    assert resolution.access_path is not None
                    for effect in resolution.effects:
                        _merge_access(effect_access, effect, resolution.access_path)

                called = (
                    model.canonical_symbol(call.ref.symbol)
                    if call.ref.state is ResolutionState.RESOLVED and call.ref.symbol is not None
                    else None
                )
                if called is not None:
                    provider = context.matching_symbol(
                        called,
                        context.policy.transaction_session_providers,
                    )
                    if provider is not None:
                        providers.add(model.canonical_symbol(provider))
                    child = summaries.get(called)
                    if child is not None:
                        providers.update(child.session_providers)
                        bulk_operations.update(child.bulk_mapping_operations)
                        for effect, access in child.effect_access.items():
                            _merge_access(effect_access, effect, access)

                operation = _bulk_mapping_operation(call.ref.symbol, call.ref.written_name)
                if operation is not None:
                    bulk_operations.add(operation)

            summary = FunctionSemanticSummary(
                FrozenMap(sorted(effect_access.items(), key=lambda item: item[0].value)),
                frozenset(providers),
                frozenset(bulk_operations),
            )
            if summaries[symbol] != summary:
                summaries[symbol] = summary
                changed = True
        if not changed:
            break
    return FrozenMap(sorted(summaries.items()))


def _merge_access(values: dict[Effect, AccessPath], effect: Effect, access: AccessPath) -> None:
    previous = values.get(effect)
    if previous is None or access is AccessPath.DIRECT:
        values[effect] = access


def _bulk_mapping_operation(symbol: SymbolId | None, written_name: str) -> str | None:
    operation = (symbol.value if symbol is not None else written_name).rsplit(".", maxsplit=1)[-1]
    return (
        operation
        if operation in {"asdict", "dict", "model_dump", "model_validate", "vars"}
        else None
    )
