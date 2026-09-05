from __future__ import annotations

from collections.abc import Iterator, Mapping
from functools import cached_property
from time import perf_counter
from types import ModuleType
from typing import Literal, Protocol, cast

from taut.configuration.catalog import AccessPath, Effect, EffectResolutionState
from taut.domain.facts import ResolutionState
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
NativeFunction = tuple[str, str, str]
NativeCalls = tuple[
    list[str], list[str], list[str | None], list[str], list[int], list[int], list[int]
]
NativeBatch = tuple[list[NativeFunction], NativeCalls, list[tuple[str, str]]]
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

    def advance_batch(self, changed: list[str], batch: NativeBatch) -> NativeState: ...
    def advance(self, changed_modules: list[str], rows: list[NativeRow]) -> NativeState: ...
    def export(self) -> list[tuple[str, NativeValue]]: ...
    def export_compact(self) -> tuple[list[NativeValue], list[tuple[str, int]]]: ...
    def export_direct(self) -> list[tuple[str, NativeValue]]: ...
    def export_graph(self) -> list[tuple[str, list[str]]]: ...
    def stats(self) -> tuple[int, int, int, int]: ...


class NativeFactory(Protocol):
    def build_batch(self, batch: NativeBatch) -> NativeState: ...
    def build(self, rows: list[NativeRow]) -> NativeState: ...


def native_extension() -> ModuleType:
    if _extension is None:
        raise RuntimeError("Rust summary backend requires the taut-summary-core wheel")
    if getattr(_extension, "CONTRACT_VERSION", None) != 1:
        raise RuntimeError("incompatible Rust summary backend contract (expected 1)")
    if getattr(_extension, "BATCH_VERSION", None) != 2:
        raise RuntimeError("Rust summary backend requires the 0.2 columnar batch extension")
    return _extension


def native_factory() -> NativeFactory:
    return cast(NativeFactory, native_extension().State)


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
    modules = (
        {symbol: module for symbol, module in prior.modules.items() if module not in invalidated}
        if prior is not None
        else {}
    )
    reused_functions = len(modules)
    functions: list[NativeFunction] = []
    calls: NativeCalls = ([], [], [], [], [], [], [])
    evaluated_calls = 0
    bits = {effect: 1 << i for i, effect in enumerate(_EFFECTS)}
    for module_id in module_ids:
        if prior is not None and module_id not in invalidated:
            continue
        module = model.module(module_id)
        owners = {function.symbol_id for function in module.functions}
        for function in module.functions:
            symbol = model.canonical_symbol(function.symbol_id)
            modules[symbol] = module_id
            functions.append((symbol.value, function.symbol_id.value, module_id.value))
        for call in module.calls:
            if call.enclosing_symbol is None or call.enclosing_symbol not in owners:
                continue
            evaluated_calls += 1
            synchronous = context.synchronous_callback_effects(call)
            uncertain = context.callback_effects(call) - synchronous
            resolution = context.effect_of(call)
            effects = sum(bits[effect] for effect in synchronous)
            direct = effects
            if resolution.state is EffectResolutionState.MATCHED:
                matched = sum(bits[effect] for effect in resolution.effects)
                effects |= matched
                if resolution.access_path is AccessPath.DIRECT:
                    direct |= matched
            called = (
                model.canonical_symbol(call.ref.symbol).value
                if call.ref.state is ResolutionState.RESOLVED and call.ref.symbol is not None
                else None
            )
            calls[0].append(call.enclosing_symbol.value)
            calls[1].append(module_id.value)
            calls[2].append(called)
            calls[3].append(
                call.ref.symbol.value if call.ref.symbol is not None else call.ref.written_name
            )
            calls[4].append(effects)
            calls[5].append(direct)
            calls[6].append(sum(bits[effect] for effect in uncertain))
    providers = [
        (candidate.value, model.canonical_symbol(candidate).value)
        for candidate in context.policy.transaction_session_providers
    ]
    prepared = perf_counter()
    batch = (functions, calls, providers)
    encoded = perf_counter()
    native = (
        native_factory().build_batch(batch)
        if prior is None
        else cast(NativeState, prior.native_handle).advance_batch(
            [module.value for module in invalidated], batch
        )
    )
    computed = perf_counter()
    summaries: dict[SymbolId, FunctionSemanticSummary] = {}
    values, bindings = native.export_compact()
    decoded_values = [decode_summary(value) for value in values]
    for name, index in bindings:
        summaries[SymbolId(name)] = decoded_values[index]
    restored = perf_counter()
    return FunctionSummaryState(
        FrozenMap(sorted(summaries.items())),
        NativeDirectView(native),
        NativeGraphView(native),
        FrozenMap(sorted(modules.items())),
        reused_functions,
        len({canonical for canonical, _, _ in functions}),
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
