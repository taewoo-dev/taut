"""Resolver-owned Tortoise ORM semantic facts."""

from __future__ import annotations

from taut.analysis.framework.indexes import grouped
from taut.analysis.framework.tortoise_facts import (
    TORTOISE_CONNECTIONS,
    TORTOISE_FIELDS,
    TORTOISE_MODELS,
    TORTOISE_PROVIDER_ID,
    TORTOISE_PROVIDER_VERSION,
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
from taut.analysis.framework.tortoise_incremental import analyze_incremental_tortoise
from taut.analysis.providers import CapabilitySpec
from taut.domain.facts import (
    CallFact,
    ClassFact,
    FieldFact,
    FunctionFact,
    ResolutionState,
    SymbolRef,
)
from taut.domain.frozen import FrozenMap
from taut.domain.ids import FactId, ModuleId, SymbolId
from taut.domain.location import SourceRange
from taut.domain.snapshot import AnalysisSnapshot

_MODEL_BASE = SymbolId("tortoise.models.Model")
_RELATION_FIELDS = frozenset({"ForeignKeyField", "ManyToManyField", "OneToOneField"})
_CONNECTION_OPERATIONS = frozenset({"get_connection", "get", "in_transaction"})
_TRANSACTION_OPERATIONS = frozenset({"atomic", "in_transaction", "commit", "rollback"})
_CONNECTION_ORIGINS = (
    "tortoise.Tortoise.get_connection",
    "tortoise.connections.get",
    "tortoise.transactions.in_transaction",
    "tortoise.backends.base.client.BaseDBAsyncClient",
    "tortoise.backends.base.client.TransactionalDBClient",
)
_WRITE_QUERIES = frozenset(
    {
        "bulk_create",
        "bulk_update",
        "create",
        "delete",
        "get_or_create",
        "save",
        "update",
        "update_or_create",
    }
)
_READ_QUERIES = frozenset(
    {
        "all",
        "annotate",
        "count",
        "exclude",
        "exists",
        "filter",
        "first",
        "get",
        "get_or_none",
        "latest",
        "earliest",
        "order_by",
        "prefetch_related",
        "select_related",
        "values",
        "values_list",
    }
)
_RAW_OPERATIONS = frozenset(
    {
        "RawSQL",
        "execute_insert",
        "execute_many",
        "execute_query",
        "execute_query_dict",
        "execute_script",
        "raw",
    }
)


__all__ = [
    "TORTOISE_CONNECTIONS",
    "TORTOISE_FIELDS",
    "TORTOISE_MODELS",
    "TORTOISE_PROVIDER_ID",
    "TORTOISE_QUERIES",
    "TORTOISE_RAW_SQL",
    "TORTOISE_RELATIONSHIPS",
    "TORTOISE_TRANSACTIONS",
    "TortoiseConnectionFact",
    "TortoiseFieldFact",
    "TortoiseModelFact",
    "TortoiseProvider",
    "TortoiseQueryFact",
    "TortoiseRawSQLFact",
    "TortoiseRelationshipFact",
    "TortoiseTransactionFact",
]


def _contains(outer: SourceRange, inner: SourceRange) -> bool:
    return (
        outer.path == inner.path
        and (
            outer.start_line,
            outer.start_column,
        )
        <= (inner.start_line, inner.start_column)
        and (
            inner.end_line,
            inner.end_column,
        )
        <= (outer.end_line, outer.end_column)
    )


def _names(ref: SymbolRef) -> frozenset[str]:
    values: set[str] = {ref.symbol.value} if ref.symbol is not None else set()
    values.update(candidate.value for candidate in ref.candidates)
    return frozenset(values)


def _operation(ref: SymbolRef, operations: frozenset[str]) -> str | None:
    return next(
        (
            name.rsplit(".", 1)[-1]
            for name in sorted(_names(ref))
            if name.rsplit(".", 1)[-1] in operations
        ),
        None,
    )


def _tortoise_origin(ref: SymbolRef) -> bool:
    return any(name == "tortoise" or name.startswith("tortoise.") for name in _names(ref))


def _has_origin(ref: SymbolRef, *prefixes: str) -> bool:
    return any(
        name == prefix or name.startswith(f"{prefix}.")
        for name in _names(ref)
        for prefix in prefixes
    )


class TortoiseProvider:
    """Extract Tortoise Model, field, query, transaction, and raw-SQL idioms."""

    id = TORTOISE_PROVIDER_ID
    version = TORTOISE_PROVIDER_VERSION
    provides = frozenset(
        CapabilitySpec(value)
        for value in (
            TORTOISE_MODELS,
            TORTOISE_FIELDS,
            TORTOISE_RELATIONSHIPS,
            TORTOISE_CONNECTIONS,
            TORTOISE_TRANSACTIONS,
            TORTOISE_QUERIES,
            TORTOISE_RAW_SQL,
        )
    )

    def analyze(self, snapshot: AnalysisSnapshot) -> FrozenMap[str, tuple[object, ...]]:
        classes = tuple(item for module in snapshot.modules.values() for item in module.classes)
        fields = tuple(item for module in snapshot.modules.values() for item in module.fields)
        functions = tuple(item for module in snapshot.modules.values() for item in module.functions)
        calls = tuple(item for module in snapshot.modules.values() for item in module.calls)
        models = self._models(snapshot, classes)
        model_symbols = frozenset(item.symbol for item in models)
        field_facts, relationships = self._fields(fields, calls, model_symbols)
        return FrozenMap(
            (
                (TORTOISE_MODELS, models),
                (TORTOISE_FIELDS, field_facts),
                (TORTOISE_RELATIONSHIPS, relationships),
                (TORTOISE_CONNECTIONS, self._connections(calls)),
                (TORTOISE_TRANSACTIONS, self._transactions(calls)),
                (TORTOISE_QUERIES, self._queries(calls, model_symbols, functions)),
                (TORTOISE_RAW_SQL, self._raw_sql(calls, model_symbols)),
            )
        )

    def analyze_incremental(
        self,
        snapshot: AnalysisSnapshot,
        previous: FrozenMap[str, tuple[object, ...]],
        impacted: frozenset[ModuleId],
    ) -> FrozenMap[str, tuple[object, ...]]:
        return analyze_incremental_tortoise(
            snapshot,
            previous,
            impacted,
            models_from=self._models,
            fields_from=self._fields,
            connections_from=self._connections,
            transactions_from=self._transactions,
            queries_from=self._queries,
            raw_sql_from=self._raw_sql,
        )

    @staticmethod
    def _models(
        snapshot: AnalysisSnapshot,
        classes: tuple[ClassFact, ...],
        inherited_models: frozenset[SymbolId] = frozenset(),
    ) -> tuple[TortoiseModelFact, ...]:
        edges_by_module = snapshot.relations.use_edges_by_module
        known = {_MODEL_BASE, *inherited_models}
        pending = list(classes)
        result: list[TortoiseModelFact] = []
        while pending:
            remaining: list[ClassFact] = []
            progressed = False
            for item in pending:
                refs = tuple(
                    next(
                        (
                            edge.ref
                            for edge in edges_by_module.get(item.module_id, ())
                            if edge.context.position.value == "base"
                            and _contains(item.location, edge.location)
                            and edge.ref.written_name == base.written
                        ),
                        SymbolRef(
                            base.written,
                            ResolutionState.RESOLVED
                            if base.symbols
                            else ResolutionState.UNRESOLVED,
                            base.symbols[0] if base.symbols else None,
                            (),
                            item.provenance,
                        ),
                    )
                    for base in item.bases
                )
                relevant = tuple(
                    ref
                    for ref in refs
                    if ref.symbol in known
                    or any(candidate in known for candidate in ref.candidates)
                )
                if not relevant:
                    remaining.append(item)
                    continue
                progressed = True
                known.add(item.symbol_id)
                confidence = relevant[0].state
                if len({candidate for ref in relevant for candidate in ref.candidates}) > 1:
                    confidence = ResolutionState.AMBIGUOUS
                result.append(
                    TortoiseModelFact(
                        item.symbol_id,
                        item.module_id,
                        item,
                        relevant,
                        relevant[0],
                        confidence,
                        item.provenance,
                    )
                )
            if not progressed:
                break
            pending = remaining
        return tuple(sorted(result, key=lambda item: (item.module_id, item.class_fact.location)))

    @staticmethod
    def _fields(
        fields: tuple[FieldFact, ...],
        calls: tuple[CallFact, ...],
        models: frozenset[SymbolId],
    ) -> tuple[tuple[TortoiseFieldFact, ...], tuple[TortoiseRelationshipFact, ...]]:
        calls_by_module = dict(grouped(calls, lambda item: item.module_id))
        result: list[TortoiseFieldFact] = []
        relationships: list[TortoiseRelationshipFact] = []
        for field in fields:
            if field.owner_symbol not in models:
                continue
            for call in calls_by_module.get(field.module_id, ()):
                if not _contains(field.location, call.location) or not _tortoise_origin(call.ref):
                    continue
                operation = next(
                    (name.rsplit(".", 1)[-1] for name in sorted(_names(call.ref))),
                    None,
                )
                if operation is None or not operation.endswith("Field"):
                    continue
                result.append(
                    TortoiseFieldFact(
                        field.owner_symbol,
                        field.module_id,
                        field,
                        call,
                        call.ref,
                        call.ref.state,
                        call.provenance,
                    )
                )
                if operation in _RELATION_FIELDS:
                    relationships.append(
                        TortoiseRelationshipFact(
                            field.owner_symbol,
                            field.module_id,
                            field,
                            call,
                            call.ref,
                            call.ref.state,
                            call.provenance,
                        )
                    )
        result.sort(key=lambda item: (item.module_id, item.field.location))
        relationships.sort(key=lambda item: (item.module_id, item.field.location))
        return tuple(result), tuple(relationships)

    @staticmethod
    def _connections(calls: tuple[CallFact, ...]) -> tuple[TortoiseConnectionFact, ...]:
        result: list[TortoiseConnectionFact] = []
        for call in calls:
            operation = _operation(call.ref, _CONNECTION_OPERATIONS)
            if operation is None or not _has_origin(
                call.ref, "tortoise.connections", "tortoise.transactions", "tortoise.Tortoise"
            ):
                continue
            result.append(
                TortoiseConnectionFact(
                    call.module_id, call, call.ref, call.ref.state, operation, call.provenance
                )
            )
        return tuple(sorted(result, key=lambda item: (item.module_id, item.call.location)))

    @staticmethod
    def _transactions(calls: tuple[CallFact, ...]) -> tuple[TortoiseTransactionFact, ...]:
        result: list[TortoiseTransactionFact] = []
        for call in calls:
            operation = _operation(call.ref, _TRANSACTION_OPERATIONS)
            if operation is None or not _has_origin(
                call.ref,
                "tortoise.transactions",
                *_CONNECTION_ORIGINS,
            ):
                continue
            result.append(
                TortoiseTransactionFact(
                    call.module_id, call, call.ref, call.ref.state, operation, call.provenance
                )
            )
        return tuple(sorted(result, key=lambda item: (item.module_id, item.call.location)))

    @staticmethod
    def _queries(
        calls: tuple[CallFact, ...],
        models: frozenset[SymbolId],
        functions: tuple[FunctionFact, ...] = (),
    ) -> tuple[TortoiseQueryFact, ...]:
        result: list[TortoiseQueryFact] = []
        operations = _READ_QUERIES | _WRITE_QUERIES
        calls_by_parent = dict(
            grouped(
                (call for call in calls if call.context.parent_fact_id is not None),
                lambda item: item.context.parent_fact_id,
            )
        )
        confidence_by_call: dict[FactId, ResolutionState] = {}
        query_returning = {
            function.symbol_id
            for function in functions
            if any(
                returned.value.rsplit(".", 1)[-1] in operations
                and any(
                    returned.value == model.value or returned.value.startswith(f"{model.value}.")
                    for model in models
                )
                for returned in function.returned_symbols
            )
        }
        changed = True
        while changed:
            changed = False
            for function in functions:
                if function.symbol_id in query_returning or not set(
                    function.returned_symbols
                ).intersection(query_returning):
                    continue
                query_returning.add(function.symbol_id)
                changed = True
        for call in calls:
            operation = _operation(call.ref, operations)
            if operation is None or not (
                _has_origin(call.ref, "tortoise.models.Model", "tortoise.queryset.QuerySet")
                or _model_origin(call.ref, models)
            ):
                continue
            confidence_by_call[call.id] = call.ref.state
            result.append(_query_fact(call, operation, call.ref.state))
        for call in calls:
            if call.ref.symbol in query_returning:
                confidence_by_call[call.id] = call.ref.state
        pending: list[CallFact] = [call for call in calls if call.id not in confidence_by_call]
        while pending:
            remaining: list[CallFact] = []
            progressed = False
            for call in pending:
                nested_confidence = next(
                    (
                        confidence_by_call[nested.id]
                        for nested in calls_by_parent.get(call.id, ())
                        if nested.id in confidence_by_call
                    ),
                    None,
                )
                operation = call.ref.written_name.rsplit(".", 1)[-1]
                if nested_confidence is None or operation not in operations:
                    remaining.append(call)
                    continue
                progressed = True
                confidence_by_call[call.id] = nested_confidence
                result.append(_query_fact(call, operation, nested_confidence))
            if not progressed:
                break
            pending = remaining
        return tuple(sorted(result, key=lambda item: (item.module_id, item.call.location)))

    @staticmethod
    def _raw_sql(
        calls: tuple[CallFact, ...], models: frozenset[SymbolId]
    ) -> tuple[TortoiseRawSQLFact, ...]:
        result: list[TortoiseRawSQLFact] = []
        for call in calls:
            operation = _operation(call.ref, _RAW_OPERATIONS)
            if operation is None or not (
                _has_origin(
                    call.ref,
                    "tortoise.expressions.RawSQL",
                    "tortoise.models.Model",
                    *_CONNECTION_ORIGINS,
                )
                or _model_origin(call.ref, models)
            ):
                continue
            first = next(
                (argument.value for argument in call.arguments if argument.position == 0), None
            )
            result.append(
                TortoiseRawSQLFact(
                    call.module_id,
                    call,
                    call.ref,
                    call.ref.state,
                    operation,
                    call.provenance,
                    first,
                    bool(first and first.literal_kind == "str"),
                    bool(first and first.literal_kind != "str"),
                )
            )
        return tuple(sorted(result, key=lambda item: (item.module_id, item.call.location)))


def _model_origin(ref: SymbolRef, models: frozenset[SymbolId]) -> bool:
    return any(
        name == model.value or name.startswith(f"{model.value}.")
        for name in _names(ref)
        for model in models
    )


def _query_fact(call: CallFact, operation: str, confidence: ResolutionState) -> TortoiseQueryFact:
    return TortoiseQueryFact(
        call.module_id,
        call,
        call.ref,
        confidence,
        operation,
        operation in _WRITE_QUERIES,
        call.provenance,
    )
