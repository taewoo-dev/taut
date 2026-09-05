from __future__ import annotations

from dataclasses import dataclass, field
from heapq import heappop, heappush
from itertools import chain
from typing import Protocol

from taut.analysis.semantic_model import SemanticModel
from taut.configuration.catalog import AccessPath, Effect, EffectResolution, EffectResolutionState
from taut.configuration.effective_policy import EffectivePolicy
from taut.domain.facts import CallFact, FunctionFact, ResolutionState
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, SymbolId


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


@dataclass(frozen=True)
class FunctionSummaryState:
    summaries: FrozenMap[SymbolId, FunctionSemanticSummary]
    direct: FrozenMap[SymbolId, FunctionSemanticSummary]
    graph: FrozenMap[SymbolId, tuple[SymbolId, ...]]
    modules: FrozenMap[SymbolId, ModuleId]
    reused_functions: int
    recomputed_functions: int
    evaluated_calls: int
    reused_components: int
    recomputed_components: int


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
    return build_function_summary_state(context).summaries


def build_function_summary_state(
    context: FunctionSummaryContext,
    prior: FunctionSummaryState | None = None,
    invalidated_modules: frozenset[ModuleId] | None = None,
) -> FunctionSummaryState:
    """Compute deterministic transitive summaries from the owned call graph.

    The context is intentionally structural here to avoid a runtime import cycle with
    ``PolicyContext``.  Its required surface is covered by policy-context tests.
    """
    model = context.model
    module_ids = model.modules()
    current_modules = frozenset(module_ids)
    invalidated = current_modules if invalidated_modules is None else invalidated_modules
    functions: dict[SymbolId, FunctionFact] = {}
    calls_by_owner: dict[tuple[ModuleId, SymbolId], list[CallFact]] = {}
    modules: dict[SymbolId, ModuleId] = {}
    graph: dict[SymbolId, frozenset[SymbolId]] = {}
    direct: dict[SymbolId, FunctionSemanticSummary] = {}
    reused_functions = 0
    if prior is not None:
        for symbol, module_id in prior.modules.items():
            if module_id in current_modules and module_id not in invalidated:
                modules[symbol] = module_id
                direct[symbol] = prior.direct[symbol]
                graph[symbol] = frozenset(prior.graph[symbol])
                reused_functions += 1

    for module_id in module_ids:
        if prior is not None and module_id not in invalidated:
            continue
        module = model.module(module_id)
        for function in module.functions:
            symbol = model.canonical_symbol(function.symbol_id)
            functions[symbol] = function
            modules[symbol] = module_id
        for call in module.calls:
            if call.enclosing_symbol is not None:
                calls_by_owner.setdefault((module_id, call.enclosing_symbol), []).append(call)
    all_symbols = frozenset(modules)
    graph = {
        symbol: frozenset(callee for callee in callees if callee in all_symbols)
        for symbol, callees in graph.items()
    }
    evaluated_calls = 0
    for symbol in sorted(functions):
        module_id = modules[symbol]
        effect_access: dict[Effect, AccessPath] = {}
        providers: set[SymbolId] = set()
        bulk_operations: set[str] = set()
        owned_callees: set[SymbolId] = set()
        function = functions[symbol]
        for call in calls_by_owner.get((module_id, function.symbol_id), ()):
            evaluated_calls += 1
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
                if called in all_symbols:
                    owned_callees.add(called)

            operation = _bulk_mapping_operation(call.ref.symbol, call.ref.written_name)
            if operation is not None:
                bulk_operations.add(operation)

        graph[symbol] = frozenset(owned_callees)
        direct[symbol] = FunctionSemanticSummary(
            FrozenMap(sorted(effect_access.items(), key=lambda item: item[0].value)),
            frozenset(providers),
            frozenset(bulk_operations),
        )

    changed_symbols = set(functions)
    if prior is not None:
        changed_symbols = {
            symbol
            for symbol in set(graph) | set(prior.graph)
            if tuple(sorted(graph.get(symbol, frozenset()))) != prior.graph.get(symbol, ())
            or direct.get(symbol) != prior.direct.get(symbol)
        }
        if not changed_symbols and set(modules) == set(prior.summaries):
            return FunctionSummaryState(
                prior.summaries,
                FrozenMap(sorted(direct.items())),
                FrozenMap(
                    (symbol, tuple(sorted(callees))) for symbol, callees in sorted(graph.items())
                ),
                FrozenMap(sorted(modules.items())),
                reused_functions,
                len(functions),
                evaluated_calls,
                prior.reused_components + prior.recomputed_components,
                0,
            )

    components = strongly_connected_components(graph)
    component_by_symbol = {
        symbol: component_index
        for component_index, component in enumerate(components)
        for symbol in component
    }
    outgoing: dict[int, set[int]] = {index: set() for index in range(len(components))}
    dependents: dict[int, set[int]] = {index: set() for index in range(len(components))}
    for symbol, callees in graph.items():
        source_component = component_by_symbol[symbol]
        for callee in callees:
            target_component = component_by_symbol[callee]
            if source_component != target_component:
                outgoing[source_component].add(target_component)
                dependents[target_component].add(source_component)

    affected_symbols = set(functions)
    if prior is not None:
        reverse_symbols: dict[SymbolId, set[SymbolId]] = {}
        for caller_symbol, called_symbols in chain(prior.graph.items(), graph.items()):
            for called_symbol in called_symbols:
                reverse_symbols.setdefault(called_symbol, set()).add(caller_symbol)
        affected_symbols = set(changed_symbols)
        pending_symbols = list(changed_symbols)
        while pending_symbols:
            changed = pending_symbols.pop()
            for caller in reverse_symbols.get(changed, ()):
                if caller not in affected_symbols:
                    affected_symbols.add(caller)
                    pending_symbols.append(caller)

    component_summaries: dict[int, FunctionSemanticSummary] = {}
    reused_components = 0
    recomputed_components = 0
    remaining = {index: len(targets) for index, targets in outgoing.items()}
    ready = sorted(index for index, count in remaining.items() if count == 0)
    while ready:
        component_index = heappop(ready)
        component = components[component_index]
        reusable = (
            prior is not None
            and affected_symbols.isdisjoint(component)
            and all(symbol in prior.summaries for symbol in component)
        )
        if reusable:
            assert prior is not None
            summary = prior.summaries[component[0]]
            reused_components += 1
        else:
            summary = FunctionSemanticSummary()
            for symbol in component:
                summary = _merge_summary(summary, direct[symbol])
            for target in sorted(outgoing[component_index]):
                summary = _merge_summary(summary, component_summaries[target])
            recomputed_components += 1
        component_summaries[component_index] = summary
        for dependent in sorted(dependents[component_index]):
            remaining[dependent] -= 1
            if remaining[dependent] == 0:
                heappush(ready, dependent)

    summaries = {symbol: component_summaries[component_by_symbol[symbol]] for symbol in modules}
    return FunctionSummaryState(
        FrozenMap(sorted(summaries.items())),
        FrozenMap(sorted(direct.items())),
        FrozenMap((symbol, tuple(sorted(callees))) for symbol, callees in sorted(graph.items())),
        FrozenMap(sorted(modules.items())),
        reused_functions,
        len(functions),
        evaluated_calls,
        reused_components,
        recomputed_components,
    )


def strongly_connected_components(
    graph: dict[SymbolId, frozenset[SymbolId]],
) -> tuple[tuple[SymbolId, ...], ...]:
    """Return deterministic SCCs without relying on Python recursion depth."""
    visited: set[SymbolId] = set()
    finished: list[SymbolId] = []
    for start in sorted(graph):
        if start in visited:
            continue
        stack: list[tuple[SymbolId, bool]] = [(start, False)]
        while stack:
            node, exiting = stack.pop()
            if exiting:
                finished.append(node)
                continue
            if node in visited:
                continue
            visited.add(node)
            stack.append((node, True))
            stack.extend((target, False) for target in sorted(graph[node], reverse=True))

    reverse: dict[SymbolId, set[SymbolId]] = {symbol: set() for symbol in graph}
    for source, targets in graph.items():
        for target in targets:
            reverse[target].add(source)

    assigned: set[SymbolId] = set()
    components: list[tuple[SymbolId, ...]] = []
    for start in reversed(finished):
        if start in assigned:
            continue
        members: list[SymbolId] = []
        pending = [start]
        assigned.add(start)
        while pending:
            node = pending.pop()
            members.append(node)
            for source in sorted(reverse[node], reverse=True):
                if source not in assigned:
                    assigned.add(source)
                    pending.append(source)
        components.append(tuple(sorted(members)))
    return tuple(sorted(components))


def _merge_summary(
    left: FunctionSemanticSummary, right: FunctionSemanticSummary
) -> FunctionSemanticSummary:
    effect_access = dict(left.effect_access.items())
    for effect, access in right.effect_access.items():
        _merge_access(effect_access, effect, access)
    return FunctionSemanticSummary(
        FrozenMap(sorted(effect_access.items(), key=lambda item: item[0].value)),
        left.session_providers | right.session_providers,
        left.bulk_mapping_operations | right.bulk_mapping_operations,
    )


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
