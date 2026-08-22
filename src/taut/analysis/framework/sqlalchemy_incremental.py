from __future__ import annotations

from collections.abc import Callable
from typing import cast

from taut.analysis.framework.sqlalchemy_facts import (
    SQLALCHEMY_MAPPED_COLUMNS,
    SQLALCHEMY_MODELS,
    SQLALCHEMY_QUERIES,
    SQLALCHEMY_RAW_SQL,
    SQLALCHEMY_RELATIONSHIPS,
    SQLALCHEMY_SESSIONS,
    SQLALCHEMY_TRANSACTIONS,
    SQLAlchemyMappedColumnFact,
    SQLAlchemyModelFact,
    SQLAlchemyQueryFact,
    SQLAlchemyRawSQLFact,
    SQLAlchemyRelationshipFact,
    SQLAlchemySessionFact,
    SQLAlchemyTransactionFact,
)
from taut.domain.facts import CallFact, ClassFact, FieldFact
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, SymbolId
from taut.domain.snapshot import AnalysisSnapshot

_FieldOwned = SQLAlchemyMappedColumnFact | SQLAlchemyRelationshipFact
_CallOwned = (
    SQLAlchemySessionFact | SQLAlchemyTransactionFact | SQLAlchemyQueryFact | SQLAlchemyRawSQLFact
)


def analyze_incremental_sqlalchemy(
    snapshot: AnalysisSnapshot,
    previous: FrozenMap[str, tuple[object, ...]],
    impacted: frozenset[ModuleId],
    *,
    models_from: Callable[
        [
            AnalysisSnapshot,
            tuple[ClassFact, ...],
            tuple[CallFact, ...],
            tuple[FieldFact, ...],
            frozenset[SymbolId],
        ],
        tuple[SQLAlchemyModelFact, ...],
    ],
    mapped_from: Callable[
        [AnalysisSnapshot, tuple[FieldFact, ...], tuple[CallFact, ...], set[SymbolId]],
        tuple[
            tuple[SQLAlchemyMappedColumnFact, ...],
            tuple[SQLAlchemyRelationshipFact, ...],
        ],
    ],
    sessions_from: Callable[
        [tuple[FieldFact, ...], tuple[CallFact, ...]], tuple[SQLAlchemySessionFact, ...]
    ],
    transactions_from: Callable[[tuple[CallFact, ...]], tuple[SQLAlchemyTransactionFact, ...]],
    queries_from: Callable[[tuple[CallFact, ...]], tuple[SQLAlchemyQueryFact, ...]],
    raw_sql_from: Callable[[tuple[CallFact, ...]], tuple[SQLAlchemyRawSQLFact, ...]],
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
    old_models = cast(tuple[SQLAlchemyModelFact, ...], previous.get(SQLALCHEMY_MODELS, ()))
    inherited = frozenset(item.symbol for item in old_models if item.module_id not in impacted)
    models = models_from(snapshot, classes, calls, fields, inherited)
    columns, relationships = mapped_from(snapshot, fields, calls, {item.symbol for item in models})
    return FrozenMap(
        (
            (SQLALCHEMY_MODELS, _merge_models(old_models, models, impacted)),
            (
                SQLALCHEMY_MAPPED_COLUMNS,
                _merge_fields(previous, SQLALCHEMY_MAPPED_COLUMNS, columns, impacted),
            ),
            (
                SQLALCHEMY_RELATIONSHIPS,
                _merge_fields(previous, SQLALCHEMY_RELATIONSHIPS, relationships, impacted),
            ),
            (
                SQLALCHEMY_SESSIONS,
                _merge_calls(
                    previous,
                    SQLALCHEMY_SESSIONS,
                    sessions_from(fields, calls),
                    impacted,
                ),
            ),
            (
                SQLALCHEMY_TRANSACTIONS,
                _merge_calls(
                    previous,
                    SQLALCHEMY_TRANSACTIONS,
                    transactions_from(calls),
                    impacted,
                ),
            ),
            (
                SQLALCHEMY_QUERIES,
                _merge_calls(previous, SQLALCHEMY_QUERIES, queries_from(calls), impacted),
            ),
            (
                SQLALCHEMY_RAW_SQL,
                _merge_calls(previous, SQLALCHEMY_RAW_SQL, raw_sql_from(calls), impacted),
            ),
        )
    )


def _merge_models(
    old: tuple[SQLAlchemyModelFact, ...],
    fresh: tuple[SQLAlchemyModelFact, ...],
    impacted: frozenset[ModuleId],
) -> tuple[SQLAlchemyModelFact, ...]:
    kept = tuple(item for item in old if item.module_id not in impacted)
    return tuple(
        sorted(
            (*kept, *fresh),
            key=lambda item: (item.module_id, item.class_fact.location, item.symbol),
        )
    )


def _merge_fields(
    previous: FrozenMap[str, tuple[object, ...]],
    capability: str,
    fresh: tuple[_FieldOwned, ...],
    impacted: frozenset[ModuleId],
) -> tuple[_FieldOwned, ...]:
    old = cast(tuple[_FieldOwned, ...], previous.get(capability, ()))
    kept = tuple(item for item in old if item.module_id not in impacted)
    return tuple(sorted((*kept, *fresh), key=lambda item: (item.module_id, item.field.location)))


def _merge_calls(
    previous: FrozenMap[str, tuple[object, ...]],
    capability: str,
    fresh: tuple[_CallOwned, ...],
    impacted: frozenset[ModuleId],
) -> tuple[_CallOwned, ...]:
    old = cast(tuple[_CallOwned, ...], previous.get(capability, ()))
    kept = tuple(item for item in old if item.module_id not in impacted)
    return tuple(sorted((*kept, *fresh), key=lambda item: (item.module_id, item.call.location)))
