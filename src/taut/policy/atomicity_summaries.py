from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from heapq import heappop, heappush
from itertools import chain
from typing import Protocol

from taut.analysis.framework.tortoise_facts import TortoiseQueryFact
from taut.analysis.semantic_model import SemanticModel
from taut.configuration.effective_policy import EffectivePolicy
from taut.domain.facts import CallFact, FunctionFact, ResolutionState
from taut.domain.frozen import FrozenMap
from taut.domain.ids import FactId, ModuleId, SymbolId

_WRITE_METHODS = frozenset(
    {
        "add",
        "add_all",
        "bulk_create",
        "bulk_update",
        "create",
        "delete",
        "flush",
        "get_or_create",
        "merge",
        "save",
        "update",
        "update_or_create",
    }
)
_BUILTIN_BOUNDARIES = frozenset(
    {
        SymbolId("tortoise.transactions.atomic"),
        SymbolId("tortoise.transactions.in_transaction"),
    }
)


@dataclass(frozen=True, order=True)
class WriteRange:
    lower: int = 0
    upper: int = 0

    def __post_init__(self) -> None:
        if not 0 <= self.lower <= self.upper <= 2:
            raise ValueError("atomicity write ranges must satisfy 0 <= lower <= upper <= 2")


@dataclass(frozen=True)
class WriteContribution:
    direct: WriteRange
    callee: SymbolId | None = None
    candidates: tuple[SymbolId, ...] = ()


@dataclass(frozen=True)
class AtomicitySummaryState:
    summaries: FrozenMap[SymbolId, WriteRange]
    contributions: FrozenMap[SymbolId, tuple[WriteContribution, ...]]
    functions: FrozenMap[SymbolId, FunctionFact]
    modules: FrozenMap[SymbolId, ModuleId]
    reused_functions: int
    recomputed_functions: int
    processed_functions: int


class AtomicitySummaryContext(Protocol):
    @property
    def model(self) -> SemanticModel: ...

    @property
    def policy(self) -> EffectivePolicy: ...

    def tortoise_query(self, fact_id: FactId) -> TortoiseQueryFact | None: ...

    def symbol_in(self, symbol: SymbolId | None, candidates: frozenset[SymbolId]) -> bool: ...


def build_atomicity_summary_state(
    context: AtomicitySummaryContext,
    prior: AtomicitySummaryState | None = None,
    invalidated_modules: frozenset[ModuleId] | None = None,
) -> AtomicitySummaryState:
    model = context.model
    module_ids = model.modules()
    current_modules = frozenset(module_ids)
    invalidated = current_modules if invalidated_modules is None else invalidated_modules
    functions: dict[SymbolId, FunctionFact] = {}
    modules: dict[SymbolId, ModuleId] = {}
    contributions: dict[SymbolId, tuple[WriteContribution, ...]] = {}
    reused_functions = 0
    if prior is not None:
        for symbol, module_id in prior.modules.items():
            if module_id in current_modules and module_id not in invalidated:
                functions[symbol] = prior.functions[symbol]
                modules[symbol] = module_id
                contributions[symbol] = prior.contributions[symbol]
                reused_functions += 1

    scanned_calls: dict[tuple[ModuleId, SymbolId], tuple[CallFact, ...]] = {}
    for module_id in module_ids:
        if prior is not None and module_id not in invalidated:
            continue
        module = model.module(module_id)
        module_function_symbols = {function.symbol_id for function in module.functions}
        calls_by_function: dict[SymbolId, list[CallFact]] = {}
        for call in module.calls:
            owner = call.enclosing_symbol
            if owner is not None and owner in module_function_symbols:
                calls_by_function.setdefault(owner, []).append(call)
        for function in module.functions:
            functions[function.symbol_id] = function
            modules[function.symbol_id] = module_id
            scanned_calls[(module_id, function.symbol_id)] = tuple(
                calls_by_function.get(function.symbol_id, ())
            )

    function_symbols = frozenset(functions)
    for symbol in sorted(set(functions).difference(contributions)):
        function = functions[symbol]
        if _decorated_boundary(function, context):
            contributions[symbol] = ()
            continue
        values: list[WriteContribution] = []
        for call in scanned_calls.get((function.module_id, symbol), ()):
            if _lexical_boundary(call, context):
                continue
            direct = _database_write_range(call, context)
            callee = (
                call.ref.symbol
                if call.ref.state is ResolutionState.RESOLVED
                and call.ref.symbol in function_symbols
                else None
            )
            candidates = tuple(
                candidate for candidate in call.ref.candidates if candidate in function_symbols
            )
            values.append(WriteContribution(direct, callee, candidates))
        contributions[symbol] = tuple(values)

    changed = set(functions)
    if prior is not None:
        changed = {
            symbol
            for symbol in set(contributions) | set(prior.contributions)
            if contributions.get(symbol) != prior.contributions.get(symbol)
        }
    reverse = _reverse_dependencies(
        chain(
            prior.contributions.items() if prior is not None else (),
            contributions.items(),
        )
    )
    affected = set(changed)
    pending = list(changed)
    while pending:
        changed_symbol = pending.pop()
        for caller in reverse.get(changed_symbol, ()):
            if caller in functions and caller not in affected:
                affected.add(caller)
                pending.append(caller)

    summaries = {
        symbol: prior.summaries.get(symbol, WriteRange()) if prior is not None else WriteRange()
        for symbol in functions
    }
    for symbol in affected:
        if symbol in summaries:
            summaries[symbol] = WriteRange()
    queue = sorted(symbol for symbol in affected if symbol in functions)
    queued = set(queue)
    processed = 0
    edge_count = sum(
        int(value.callee is not None) + len(value.candidates)
        for symbol in affected
        for value in contributions.get(symbol, ())
    )
    limit = max(1, len(affected) * 8 + edge_count * 4)
    while queue:
        symbol = heappop(queue)
        queued.remove(symbol)
        processed += 1
        if processed > limit:
            raise RuntimeError("atomicity summary propagation exceeded its bounded work limit")
        summary = _evaluate(contributions[symbol], summaries)
        if summary == summaries[symbol]:
            continue
        summaries[symbol] = summary
        for caller in sorted(reverse.get(symbol, ())):
            if caller in affected and caller not in queued:
                heappush(queue, caller)
                queued.add(caller)

    return AtomicitySummaryState(
        FrozenMap(sorted(summaries.items())),
        FrozenMap(sorted(contributions.items())),
        FrozenMap(sorted(functions.items())),
        FrozenMap(sorted(modules.items())),
        reused_functions,
        len(functions) - reused_functions,
        processed,
    )


def _reverse_dependencies(
    entries: Iterable[tuple[SymbolId, tuple[WriteContribution, ...]]],
) -> dict[SymbolId, set[SymbolId]]:
    reverse: dict[SymbolId, set[SymbolId]] = {}
    for caller, values in entries:
        for value in values:
            dependencies = (value.callee,) if value.callee is not None else value.candidates
            for dependency in dependencies:
                reverse.setdefault(dependency, set()).add(caller)
    return reverse


def _evaluate(
    contributions: tuple[WriteContribution, ...],
    summaries: dict[SymbolId, WriteRange],
) -> WriteRange:
    lower = 0
    upper = 0
    for contribution in contributions:
        direct_lower = contribution.direct.lower
        direct_upper = contribution.direct.upper
        if contribution.callee is not None:
            child = summaries[contribution.callee]
            direct_lower += child.lower
            direct_upper += child.upper
        elif contribution.candidates:
            direct_upper += max(summaries[item].upper for item in contribution.candidates)
        lower = min(lower + direct_lower, 2)
        upper = min(upper + direct_upper, 2)
    return WriteRange(lower, upper)


def _decorated_boundary(function: FunctionFact, context: AtomicitySummaryContext) -> bool:
    allowed = context.policy.transaction_boundary_decorators.union(_BUILTIN_BOUNDARIES)
    module = context.model.module(function.module_id)
    return any(
        item.decorated_symbol == function.symbol_id and context.symbol_in(item.ref.symbol, allowed)
        for item in module.decorators
    )


def _lexical_boundary(call: CallFact, context: AtomicitySummaryContext) -> bool:
    allowed = context.policy.transaction_boundary_contexts.union(_BUILTIN_BOUNDARIES)
    return any(context.symbol_in(item.symbol, allowed) for item in call.enclosing_contexts)


def _database_write_range(call: CallFact, context: AtomicitySummaryContext) -> WriteRange:
    tortoise = context.tortoise_query(call.id)
    if tortoise is not None and tortoise.is_write:
        return (
            WriteRange(1, 1)
            if tortoise.confidence is ResolutionState.RESOLVED
            else WriteRange(0, 1)
        )
    symbol = call.ref.symbol
    if call.ref.state is ResolutionState.RESOLVED and symbol is not None:
        canonical = context.model.canonical_symbol(symbol).value
        method = canonical.rsplit(".", maxsplit=1)[-1]
        if method in _WRITE_METHODS and canonical.startswith("sqlalchemy."):
            return WriteRange(1, 1)
    method = call.ref.written_name.rsplit(".", maxsplit=1)[-1]
    if method not in _WRITE_METHODS:
        return WriteRange()
    root = call.ref.written_name.split(".", maxsplit=1)[0].split("(", maxsplit=1)[0]
    module = context.model.module(call.module_id)
    grounded = any(
        class_fact.name == root
        and any(
            base_symbol.value == "tortoise.models.Model"
            for base in class_fact.bases
            for base_symbol in base.symbols
        )
        for class_fact in module.classes
    )
    return WriteRange(1, 1) if grounded else WriteRange()
