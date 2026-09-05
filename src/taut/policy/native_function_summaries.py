from __future__ import annotations

from collections.abc import Iterator, Mapping
from functools import cached_property
from time import perf_counter
from types import ModuleType
from typing import Literal, Protocol, cast

from taut.configuration.catalog import AccessPath, Effect, EffectResolutionState
from taut.domain.facts import CallFact, FunctionFact, ResolutionState
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, SymbolId
from taut.policy.function_summaries import (
    FunctionSemanticSummary,
    FunctionSummaryContext,
    FunctionSummaryState,
)

try:
    import _taut_summary_core as _native_extension  # pyright: ignore[reportMissingModuleSource]
except ImportError:
    _extension: ModuleType | None = None
else:
    _extension = _native_extension

SummaryBackend = Literal["python", "rust"]
NativeValue = tuple[int, int, list[str], list[str], int]
NativeRow = tuple[str, str, list[str], NativeValue]
# Contract v1 bit order; changes require a coordinated contract bump.
_EFFECTS = (
    Effect.EXTERNAL_CALL,
    Effect.IO_BLOCKING,
    Effect.SECURITY_ENVIRONMENT,
    Effect.SECURITY_SECRET,
    Effect.SECURITY_TOKEN,
    Effect.TIME_NOW,
    Effect.TX_COMMIT,
    Effect.TX_ROLLBACK,
)


class NativeState(Protocol):
    reused_components: int
    recomputed_components: int
    compute_seconds: float

    def advance(self, changed_modules: list[str], rows: list[NativeRow]) -> NativeState: ...
    def export(self) -> list[tuple[str, NativeValue]]: ...
    def export_compact(self) -> tuple[list[NativeValue], list[tuple[str, int]]]: ...
    def export_direct(self) -> list[tuple[str, NativeValue]]: ...
    def export_graph(self) -> list[tuple[str, list[str]]]: ...
    def stats(self) -> tuple[int, int, int, int]: ...


class NativeFactory(Protocol):
    def build(self, rows: list[NativeRow]) -> NativeState: ...


def native_factory() -> NativeFactory:
    if _extension is None:
        raise RuntimeError("Rust summary backend requires the taut-summary-core wheel")
    if getattr(_extension, "CONTRACT_VERSION", None) != 1:
        raise RuntimeError("incompatible Rust summary backend contract (expected 1)")
    return cast(NativeFactory, _extension.State)


def validate_summary_backend(backend: SummaryBackend) -> None:
    if backend == "rust":
        native_factory()
    elif backend != "python":
        raise ValueError(f"unknown summary backend: {backend}")


def encode_summary(summary: FunctionSemanticSummary) -> NativeValue:
    return (
        sum(1 << i for i, effect in enumerate(_EFFECTS) if effect in summary.effect_access),
        sum(
            1 << i
            for i, effect in enumerate(_EFFECTS)
            if summary.effect_access.get(effect) is AccessPath.DIRECT
        ),
        sorted(symbol.value for symbol in summary.session_providers),
        sorted(summary.bulk_mapping_operations),
        sum(1 << i for i, effect in enumerate(_EFFECTS) if effect in summary.uncertain_effects),
    )


def decode_summary(value: NativeValue) -> FunctionSemanticSummary:
    effects, direct, providers, bulk, uncertain = value
    return FunctionSemanticSummary(
        FrozenMap(
            (effect, AccessPath.DIRECT if direct & (1 << i) else AccessPath.APPROVED_WRAPPER)
            for i, effect in enumerate(_EFFECTS)
            if effects & (1 << i)
        ),
        frozenset(SymbolId(symbol) for symbol in providers),
        frozenset(bulk),
        frozenset(effect for i, effect in enumerate(_EFFECTS) if uncertain & (1 << i)),
    )


def build_native_function_summary_state(
    context: FunctionSummaryContext,
    prior: FunctionSummaryState | None = None,
    invalidated_modules: frozenset[ModuleId] | None = None,
) -> FunctionSummaryState:
    started = perf_counter()
    if prior is not None and (
        prior.native_handle is None or prior.native_modules != frozenset(context.model.modules())
    ):
        prior = None
    model = context.model
    module_ids = model.modules()
    current_modules = frozenset(module_ids)
    invalidated = current_modules if invalidated_modules is None else invalidated_modules
    functions: dict[SymbolId, FunctionFact] = {}
    calls_by_owner: dict[tuple[ModuleId, SymbolId], list[CallFact]] = {}
    modules: dict[SymbolId, ModuleId] = {}
    graph: dict[SymbolId, frozenset[SymbolId]] = {}
    direct: dict[SymbolId, FunctionSemanticSummary] = {}
    summary_values: dict[FunctionSemanticSummary, FunctionSemanticSummary] = {}

    def canonical_summary(summary: FunctionSemanticSummary) -> FunctionSemanticSummary:
        # Full immutable values, including uncertainty and access paths, define equality.
        # The pool belongs to this build and does not retain previous revisions globally.
        return summary_values.setdefault(summary, summary)

    # Rust retains unchanged inputs; Python only reconstructs the changed batch.
    for module_id in module_ids:
        for function in model.module(module_id).functions:
            modules[model.canonical_symbol(function.symbol_id)] = module_id
    reused_functions = sum(module not in invalidated for module in modules.values()) if prior else 0

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
        uncertain_effects: set[Effect] = set()
        bulk_operations: set[str] = set()
        owned_callees: set[SymbolId] = set()
        function = functions[symbol]
        for call in calls_by_owner.get((module_id, function.symbol_id), ()):
            evaluated_calls += 1
            synchronous = context.synchronous_callback_effects(call)
            uncertain_effects.update(context.callback_effects(call) - synchronous)
            for effect in synchronous:
                _merge_access(effect_access, effect, AccessPath.DIRECT)
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
        direct[symbol] = canonical_summary(
            FunctionSemanticSummary(
                FrozenMap(sorted(effect_access.items(), key=lambda item: item[0].value)),
                frozenset(providers),
                frozenset(bulk_operations),
                frozenset(uncertain_effects),
            )
        )

    prepared = perf_counter()
    rows: list[NativeRow] = [
        (
            symbol.value,
            modules[symbol].value,
            sorted(callee.value for callee in graph[symbol]),
            encode_summary(direct[symbol]),
        )
        for symbol in sorted(functions)
    ]
    encoded = perf_counter()
    if prior is None:
        native = native_factory().build(rows)
    else:
        native = cast(NativeState, prior.native_handle).advance(
            sorted(module.value for module in invalidated), rows
        )
    computed = perf_counter()
    summaries: dict[SymbolId, FunctionSemanticSummary] = {}
    values, bindings = native.export_compact()
    decoded_values = [canonical_summary(decode_summary(value)) for value in values]
    for name, index in bindings:
        summaries[SymbolId(name)] = decoded_values[index]
    restored = perf_counter()
    return FunctionSummaryState(
        FrozenMap(sorted(summaries.items())),
        NativeDirectView(native),
        NativeGraphView(native),
        FrozenMap(sorted(modules.items())),
        reused_functions,
        len(functions),
        evaluated_calls,
        native.reused_components,
        native.recomputed_components,
        native,
        current_modules,
        (
            prepared - started,
            encoded - prepared,
            computed - encoded - native.compute_seconds,
            native.compute_seconds,
            restored - computed,
            restored - started,
        ),
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


class NativeDirectView(Mapping[SymbolId, FunctionSemanticSummary]):
    """Bulk materialize diagnostics-only state once, on demand."""

    def __init__(self, native: NativeState) -> None:
        self._native = native

    @cached_property
    def values_map(self) -> FrozenMap[SymbolId, FunctionSemanticSummary]:
        pool: dict[FunctionSemanticSummary, FunctionSemanticSummary] = {}
        values: dict[SymbolId, FunctionSemanticSummary] = {}
        for name, value in self._native.export_direct():
            summary = decode_summary(value)
            values[SymbolId(name)] = pool.setdefault(summary, summary)
        return FrozenMap(values)

    def __getitem__(self, key: SymbolId) -> FunctionSemanticSummary:
        return self.values_map[key]

    def __iter__(self) -> Iterator[SymbolId]:
        return iter(self.values_map)

    def __len__(self) -> int:
        return self._native.stats()[0]


class NativeGraphView(Mapping[SymbolId, tuple[SymbolId, ...]]):
    def __init__(self, native: NativeState) -> None:
        self._native = native

    @cached_property
    def values_map(self) -> FrozenMap[SymbolId, tuple[SymbolId, ...]]:
        return FrozenMap(
            (SymbolId(name), tuple(SymbolId(c) for c in calls))
            for name, calls in self._native.export_graph()
        )

    def __getitem__(self, key: SymbolId) -> tuple[SymbolId, ...]:
        return self.values_map[key]

    def __iter__(self) -> Iterator[SymbolId]:
        return iter(self.values_map)

    def __len__(self) -> int:
        return self._native.stats()[0]
