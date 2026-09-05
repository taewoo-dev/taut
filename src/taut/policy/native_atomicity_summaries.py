from __future__ import annotations

from collections.abc import Iterator, Mapping
from functools import cached_property
from typing import Protocol, cast

from taut.domain.facts import FunctionFact, ResolutionState
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, SymbolId
from taut.policy.atomicity_summaries import (
    AtomicitySummaryContext,
    AtomicitySummaryState,
    WriteContribution,
    WriteRange,
)
from taut.policy.native_function_summaries import native_extension

AtomicFunction = tuple[str, str, list[str]]
AtomicCalls = tuple[
    list[str],
    list[str],
    list[str | None],
    list[str | None],
    list[tuple[str, ...]],
    list[str],
    list[tuple[str, ...]],
    list[int],
]
AtomicBatch = tuple[
    list[AtomicFunction], AtomicCalls, list[tuple[str, list[str]]], list[str], list[str]
]
AtomicContribution = tuple[tuple[int, int], str | None, list[str]]
_BUILTINS = frozenset(
    {SymbolId("tortoise.transactions.atomic"), SymbolId("tortoise.transactions.in_transaction")}
)


class NativeAtomicState(Protocol):
    processed_functions: int
    compute_seconds: float

    def advance(self, changed: list[str], batch: AtomicBatch) -> NativeAtomicState: ...
    def export(self) -> list[tuple[str, tuple[int, int]]]: ...
    def export_contributions(self) -> list[tuple[str, list[AtomicContribution]]]: ...


class AtomicFactory(Protocol):
    def build(self, batch: AtomicBatch) -> NativeAtomicState: ...


def build_native_atomicity_summary_state(
    context: AtomicitySummaryContext,
    prior: AtomicitySummaryState | None = None,
    invalidated_modules: frozenset[ModuleId] | None = None,
) -> AtomicitySummaryState:
    model = context.model
    current = frozenset(model.modules())
    if prior is not None and (prior.native_handle is None or prior.native_modules != current):
        prior = None
    invalidated = current if invalidated_modules is None else invalidated_modules
    functions: dict[SymbolId, FunctionFact] = {}
    modules: dict[SymbolId, ModuleId] = {}
    if prior is not None:
        for symbol, previous_module in prior.modules.items():
            if previous_module not in invalidated:
                functions[symbol] = prior.functions[symbol]
                modules[symbol] = previous_module
    reused = len(functions)
    definitions: list[AtomicFunction] = []
    calls: AtomicCalls = ([], [], [], [], [], [], [], [])
    grounded: list[tuple[str, list[str]]] = []
    for module_id in model.modules():
        if prior is not None and module_id not in invalidated:
            continue
        module = model.module(module_id)
        decorators: dict[SymbolId, list[str]] = {}
        for item in module.decorators:
            if item.ref.symbol is not None:
                decorators.setdefault(item.decorated_symbol, []).append(
                    model.canonical_symbol(item.ref.symbol).value
                )
        owners = {function.symbol_id for function in module.functions}
        for function in module.functions:
            functions[function.symbol_id] = function
            modules[function.symbol_id] = module_id
            definitions.append(
                (function.symbol_id.value, module_id.value, decorators.get(function.symbol_id, []))
            )
        grounded.append(
            (
                module_id.value,
                [
                    c.name
                    for c in module.classes
                    if any(
                        symbol.value == "tortoise.models.Model"
                        for base in c.bases
                        for symbol in base.symbols
                    )
                ],
            )
        )
        for call in module.calls:
            if call.enclosing_symbol is None or call.enclosing_symbol not in owners:
                continue
            resolved = call.ref.symbol if call.ref.state is ResolutionState.RESOLVED else None
            query = context.database_query(call.id)
            query_kind = (
                (1 if query.confidence is ResolutionState.RESOLVED else 2)
                if query is not None and query.is_write
                else 0
            )
            calls[0].append(call.enclosing_symbol.value)
            calls[1].append(module_id.value)
            calls[2].append(resolved.value if resolved is not None else None)
            calls[3].append(
                model.canonical_symbol(resolved).value if resolved is not None else None
            )
            calls[4].append(tuple(symbol.value for symbol in call.ref.candidates))
            calls[5].append(call.ref.written_name)
            calls[6].append(
                tuple(
                    model.canonical_symbol(item.symbol).value
                    for item in call.enclosing_contexts
                    if item.symbol is not None
                )
            )
            calls[7].append(query_kind)
    batch = (
        definitions,
        calls,
        grounded,
        [
            model.canonical_symbol(symbol).value
            for symbol in context.policy.transaction_boundary_decorators | _BUILTINS
        ],
        [
            model.canonical_symbol(symbol).value
            for symbol in context.policy.transaction_boundary_contexts | _BUILTINS
        ],
    )
    factory = cast(AtomicFactory, native_extension().AtomicState)
    native = (
        factory.build(batch)
        if prior is None
        else cast(NativeAtomicState, prior.native_handle).advance(
            [module.value for module in invalidated], batch
        )
    )
    pool: dict[tuple[int, int], WriteRange] = {}
    summaries: dict[SymbolId, WriteRange] = {}
    for name, value in native.export():
        if value not in pool:
            pool[value] = WriteRange(*value)
        summaries[SymbolId(name)] = pool[value]
    return AtomicitySummaryState(
        FrozenMap(summaries),
        NativeContributions(native),
        FrozenMap(sorted(functions.items())),
        FrozenMap(sorted(modules.items())),
        reused,
        len(functions) - reused,
        native.processed_functions,
        native,
        current,
    )


class NativeContributions(Mapping[SymbolId, tuple[WriteContribution, ...]]):
    def __init__(self, native: NativeAtomicState) -> None:
        self.native = native

    @cached_property
    def values_map(self) -> FrozenMap[SymbolId, tuple[WriteContribution, ...]]:
        return FrozenMap(
            (
                SymbolId(symbol),
                tuple(
                    WriteContribution(
                        WriteRange(*value),
                        SymbolId(callee) if callee is not None else None,
                        tuple(SymbolId(c) for c in candidates),
                    )
                    for value, callee, candidates in contributions
                ),
            )
            for symbol, contributions in self.native.export_contributions()
        )

    def __getitem__(self, key: SymbolId) -> tuple[WriteContribution, ...]:
        return self.values_map[key]

    def __iter__(self) -> Iterator[SymbolId]:
        return iter(self.values_map)

    def __len__(self) -> int:
        return len(self.values_map)
