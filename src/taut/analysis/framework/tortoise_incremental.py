from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol, cast

from taut.analysis.framework.tortoise_facts import (
    TORTOISE_CONNECTIONS,
    TORTOISE_FIELDS,
    TORTOISE_MODELS,
    TORTOISE_QUERIES,
    TORTOISE_RAW_SQL,
    TORTOISE_RELATIONSHIPS,
    TORTOISE_TRANSACTIONS,
    TortoiseConnectionFact,
    TortoiseFieldFact,
    TortoiseModelFact,
    TortoiseQueryFact,
    TortoiseRawSQLFact,
    TortoiseRelationshipFact,
    TortoiseTransactionFact,
)
from taut.domain.facts import CallFact, ClassFact, FieldFact
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, SymbolId
from taut.domain.snapshot import AnalysisSnapshot


class _ModuleOwned(Protocol):
    @property
    def module_id(self) -> ModuleId: ...


def analyze_incremental_tortoise(
    snapshot: AnalysisSnapshot,
    previous: FrozenMap[str, tuple[object, ...]],
    impacted: frozenset[ModuleId],
    *,
    models_from: Callable[
        [AnalysisSnapshot, tuple[ClassFact, ...], frozenset[SymbolId]],
        tuple[TortoiseModelFact, ...],
    ],
    fields_from: Callable[
        [tuple[FieldFact, ...], tuple[CallFact, ...], frozenset[SymbolId]],
        tuple[tuple[TortoiseFieldFact, ...], tuple[TortoiseRelationshipFact, ...]],
    ],
    connections_from: Callable[[tuple[CallFact, ...]], tuple[TortoiseConnectionFact, ...]],
    transactions_from: Callable[[tuple[CallFact, ...]], tuple[TortoiseTransactionFact, ...]],
    queries_from: Callable[
        [tuple[CallFact, ...], frozenset[SymbolId]], tuple[TortoiseQueryFact, ...]
    ],
    raw_sql_from: Callable[
        [tuple[CallFact, ...], frozenset[SymbolId]], tuple[TortoiseRawSQLFact, ...]
    ],
) -> FrozenMap[str, tuple[object, ...]]:
    if not impacted:
        return FrozenMap(previous.items())
    selected = tuple(
        snapshot.modules[module_id]
        for module_id in sorted(impacted)
        if module_id in snapshot.modules
    )
    classes = tuple(item for module in selected for item in module.classes)
    fields = tuple(item for module in selected for item in module.fields)
    calls = tuple(item for module in selected for item in module.calls)
    old_models = cast(tuple[TortoiseModelFact, ...], previous.get(TORTOISE_MODELS, ()))
    inherited = frozenset(item.symbol for item in old_models if item.module_id not in impacted)
    fresh_models = models_from(snapshot, classes, inherited)
    all_models = inherited | frozenset(item.symbol for item in fresh_models)
    fresh_fields, fresh_relationships = fields_from(fields, calls, all_models)
    return FrozenMap(
        (
            (
                TORTOISE_MODELS,
                _merge(
                    old_models,
                    fresh_models,
                    impacted,
                    lambda item: (item.module_id, item.class_fact.location),
                ),
            ),
            (
                TORTOISE_FIELDS,
                _merge_capability(
                    previous,
                    TORTOISE_FIELDS,
                    fresh_fields,
                    impacted,
                    lambda item: (item.module_id, item.field.location),
                ),
            ),
            (
                TORTOISE_RELATIONSHIPS,
                _merge_capability(
                    previous,
                    TORTOISE_RELATIONSHIPS,
                    fresh_relationships,
                    impacted,
                    lambda item: (item.module_id, item.field.location),
                ),
            ),
            (
                TORTOISE_CONNECTIONS,
                _merge_capability(
                    previous,
                    TORTOISE_CONNECTIONS,
                    connections_from(calls),
                    impacted,
                    lambda item: (item.module_id, item.call.location),
                ),
            ),
            (
                TORTOISE_TRANSACTIONS,
                _merge_capability(
                    previous,
                    TORTOISE_TRANSACTIONS,
                    transactions_from(calls),
                    impacted,
                    lambda item: (item.module_id, item.call.location),
                ),
            ),
            (
                TORTOISE_QUERIES,
                _merge_capability(
                    previous,
                    TORTOISE_QUERIES,
                    queries_from(calls, all_models),
                    impacted,
                    lambda item: (item.module_id, item.call.location),
                ),
            ),
            (
                TORTOISE_RAW_SQL,
                _merge_capability(
                    previous,
                    TORTOISE_RAW_SQL,
                    raw_sql_from(calls, all_models),
                    impacted,
                    lambda item: (item.module_id, item.call.location),
                ),
            ),
        )
    )


def _merge[T: _ModuleOwned](
    old: tuple[T, ...],
    fresh: tuple[T, ...],
    impacted: frozenset[ModuleId],
    key: Callable[[T], Any],
) -> tuple[T, ...]:
    kept = tuple(item for item in old if item.module_id not in impacted)
    return tuple(sorted((*kept, *fresh), key=key))


def _merge_capability[T: _ModuleOwned](
    previous: FrozenMap[str, tuple[object, ...]],
    capability: str,
    fresh: tuple[T, ...],
    impacted: frozenset[ModuleId],
    key: Callable[[T], Any],
) -> tuple[T, ...]:
    return _merge(cast(tuple[T, ...], previous.get(capability, ())), fresh, impacted, key)
