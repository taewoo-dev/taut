"""Resolver-owned SQLAlchemy semantic facts."""

from __future__ import annotations

from taut.analysis.framework.sqlalchemy_facts import (
    COLUMN_CALLS,
    MODEL_BASES,
    QUERY_NAMES,
    RELATIONSHIP_CALL,
    SESSION_FACTORIES,
    SESSION_TYPES,
    SQLALCHEMY_MAPPED_COLUMNS,
    SQLALCHEMY_MODELS,
    SQLALCHEMY_PROVIDER_ID,
    SQLALCHEMY_PROVIDER_VERSION,
    SQLALCHEMY_QUERIES,
    SQLALCHEMY_RAW_SQL,
    SQLALCHEMY_RELATIONSHIPS,
    SQLALCHEMY_SESSIONS,
    SQLALCHEMY_TRANSACTIONS,
    TX_NAMES,
    SQLAlchemyMappedColumnFact,
    SQLAlchemyModelFact,
    SQLAlchemyQueryFact,
    SQLAlchemyRawSQLFact,
    SQLAlchemyRelationshipFact,
    SQLAlchemySessionFact,
    SQLAlchemyTransactionFact,
)
from taut.analysis.providers import CapabilitySpec
from taut.domain.facts import CallFact, ClassFact, FieldFact, ResolutionState, SymbolRef
from taut.domain.frozen import FrozenMap
from taut.domain.ids import SymbolId
from taut.domain.location import SourceRange
from taut.domain.snapshot import AnalysisSnapshot

__all__ = [
    "SQLALCHEMY_MAPPED_COLUMNS",
    "SQLALCHEMY_MODELS",
    "SQLALCHEMY_PROVIDER_ID",
    "SQLALCHEMY_QUERIES",
    "SQLALCHEMY_RAW_SQL",
    "SQLALCHEMY_RELATIONSHIPS",
    "SQLALCHEMY_SESSIONS",
    "SQLALCHEMY_TRANSACTIONS",
    "SQLAlchemyColumnFact",
    "SQLAlchemyConfidence",
    "SQLAlchemyMappedColumnFact",
    "SQLAlchemyModelFact",
    "SQLAlchemyProvider",
    "SQLAlchemyQuery",
    "SQLAlchemyQueryFact",
    "SQLAlchemyRawSQL",
    "SQLAlchemyRawSQLFact",
    "SQLAlchemyRelationshipFact",
    "SQLAlchemySession",
    "SQLAlchemySessionFact",
    "SQLAlchemyTransaction",
    "SQLAlchemyTransactionFact",
]


def _contains(outer: SourceRange, inner: SourceRange) -> bool:
    if outer.path != inner.path:
        return False
    return (outer.start_line, outer.start_column) <= (inner.start_line, inner.start_column) and (
        inner.end_line,
        inner.end_column,
    ) <= (outer.end_line, outer.end_column)


def _names(ref: SymbolRef) -> frozenset[str]:
    values: set[str] = {ref.symbol.value} if ref.symbol is not None else set()
    values.update(candidate.value for candidate in ref.candidates)
    return frozenset(values)


def _sqlalchemy_name(ref: SymbolRef, suffixes: frozenset[str]) -> bool:
    names = _names(ref)
    return any(
        name.startswith("sqlalchemy.") and name.rsplit(".", 1)[-1] in suffixes for name in names
    )


def _is_async(ref: SymbolRef) -> bool:
    return any(name.startswith("sqlalchemy.ext.asyncio.") for name in _names(ref))


class SQLAlchemyProvider:
    """Extract SQLAlchemy 1.4 and 2.x idioms from resolver-owned semantic facts."""

    id = SQLALCHEMY_PROVIDER_ID
    version = SQLALCHEMY_PROVIDER_VERSION
    provides = frozenset(
        CapabilitySpec(value)
        for value in (
            SQLALCHEMY_MODELS,
            SQLALCHEMY_MAPPED_COLUMNS,
            SQLALCHEMY_RELATIONSHIPS,
            SQLALCHEMY_SESSIONS,
            SQLALCHEMY_TRANSACTIONS,
            SQLALCHEMY_QUERIES,
            SQLALCHEMY_RAW_SQL,
        )
    )

    def analyze(self, snapshot: AnalysisSnapshot) -> FrozenMap[str, tuple[object, ...]]:
        classes = tuple(item for module in snapshot.modules.values() for item in module.classes)
        fields = tuple(item for module in snapshot.modules.values() for item in module.fields)
        calls = tuple(item for module in snapshot.modules.values() for item in module.calls)
        models = self._models(snapshot, classes, calls)
        model_symbols = {item.symbol for item in models}
        columns, relationships = self._mapped(snapshot, fields, calls, model_symbols)
        sessions = self._sessions(fields, calls)
        transactions = self._transactions(calls)
        queries = self._queries(calls)
        raw_sql = self._raw_sql(calls)
        return FrozenMap(
            (
                (SQLALCHEMY_MODELS, models),
                (SQLALCHEMY_MAPPED_COLUMNS, columns),
                (SQLALCHEMY_RELATIONSHIPS, relationships),
                (SQLALCHEMY_SESSIONS, sessions),
                (SQLALCHEMY_TRANSACTIONS, transactions),
                (SQLALCHEMY_QUERIES, queries),
                (SQLALCHEMY_RAW_SQL, raw_sql),
            )
        )

    def _models(
        self,
        snapshot: AnalysisSnapshot,
        classes: tuple[ClassFact, ...],
        calls: tuple[CallFact, ...],
    ) -> tuple[SQLAlchemyModelFact, ...]:
        declarative_bases = {
            binding.target.symbol
            for binding in snapshot.relations.bindings
            if any(
                call.module_id == binding.module_id
                and call.ref.symbol
                in {
                    SymbolId("sqlalchemy.orm.declarative_base"),
                    SymbolId("sqlalchemy.ext.declarative.declarative_base"),
                }
                and call.context.parent_fact_id is None
                and _contains(binding.location, call.location)
                for call in calls
            )
            if binding.target.symbol is not None
        }
        direct_bases = {SymbolId(value) for value in MODEL_BASES} | declarative_bases
        result: list[SQLAlchemyModelFact] = []
        known: set[SymbolId] = set(direct_bases)
        pending = list(classes)
        while pending:
            remaining: list[ClassFact] = []
            progressed = False
            for item in pending:
                refs = tuple(
                    next(
                        (
                            edge.ref
                            for edge in snapshot.relations.use_edges
                            if edge.module_id == item.module_id
                            and edge.purpose.value == "base"
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
                    SQLAlchemyModelFact(
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
        return tuple(
            sorted(result, key=lambda item: (item.module_id, item.class_fact.location, item.symbol))
        )

    def _mapped(
        self,
        snapshot: AnalysisSnapshot,
        fields: tuple[FieldFact, ...],
        calls: tuple[CallFact, ...],
        models: set[SymbolId],
    ) -> tuple[tuple[SQLAlchemyMappedColumnFact, ...], tuple[SQLAlchemyRelationshipFact, ...]]:
        columns: list[SQLAlchemyMappedColumnFact] = []
        relationships: list[SQLAlchemyRelationshipFact] = []
        for field in fields:
            if field.owner_symbol not in models:
                continue
            nested = tuple(
                call
                for call in calls
                if call.module_id == field.module_id
                and _contains(field.location, call.location)
                and (call.context.parent_fact_id == field.id or call.context.parent_fact_id is None)
            )
            for call in nested:
                if call.ref.symbol in {SymbolId(value) for value in COLUMN_CALLS} or _names(
                    call.ref
                ).intersection(COLUMN_CALLS):
                    columns.append(
                        SQLAlchemyMappedColumnFact(
                            field.owner_symbol,
                            field.module_id,
                            field,
                            call,
                            call.ref,
                            call.ref.state,
                            call.provenance,
                        )
                    )
                if call.ref.symbol == SymbolId(RELATIONSHIP_CALL) or RELATIONSHIP_CALL in _names(
                    call.ref
                ):
                    relationships.append(
                        SQLAlchemyRelationshipFact(
                            field.owner_symbol,
                            field.module_id,
                            field,
                            call,
                            call.ref,
                            call.ref.state,
                            call.provenance,
                        )
                    )
            if (
                field.value is None
                and field.annotation is not None
                and any(
                    symbol.value == "sqlalchemy.orm.Mapped" for symbol in field.annotation.symbols
                )
            ):
                annotation_ref = next(
                    (
                        edge.ref
                        for edge in snapshot.relations.use_edges
                        if edge.module_id == field.module_id
                        and edge.context.position.value == "annotation"
                        and _contains(field.location, edge.location)
                    ),
                    SymbolRef(
                        field.annotation.written,
                        ResolutionState.RESOLVED
                        if field.annotation.symbols
                        else ResolutionState.UNRESOLVED,
                        next(iter(field.annotation.symbols), None),
                        (),
                        field.provenance,
                    ),
                )
                columns.append(
                    SQLAlchemyMappedColumnFact(
                        field.owner_symbol,
                        field.module_id,
                        field,
                        None,
                        annotation_ref,
                        annotation_ref.state,
                        field.provenance,
                    )
                )
        columns.sort(key=lambda item: (item.module_id, item.field.location))
        relationships.sort(key=lambda item: (item.module_id, item.field.location))
        return tuple(columns), tuple(relationships)

    def _sessions(
        self, fields: tuple[FieldFact, ...], calls: tuple[CallFact, ...]
    ) -> tuple[SQLAlchemySessionFact, ...]:
        result: list[SQLAlchemySessionFact] = []
        factory_origins: dict[SymbolId, tuple[SymbolRef, bool]] = {}
        for call in calls:
            if not _names(call.ref).intersection(SESSION_FACTORIES):
                continue
            for field in fields:
                if (
                    call.context.parent_fact_id is not None
                    or field.module_id != call.module_id
                    or not _contains(field.location, call.location)
                ):
                    continue
                factory_origins[field.symbol_id] = (call.ref, _is_async(call.ref))
        for call in calls:
            names = _names(call.ref)
            kind = next(
                (
                    name.rsplit(".", 1)[-1]
                    for name in names
                    if name in SESSION_TYPES | SESSION_FACTORIES
                ),
                None,
            )
            if (
                _names(call.ref).intersection(SESSION_FACTORIES)
                and call.context.parent_fact_id is not None
            ):
                continue
            origin = factory_origins.get(call.ref.symbol) if call.ref.symbol is not None else None
            if kind is None and origin is None:
                continue
            if kind is None:
                kind = "AsyncSession" if origin and origin[1] else "Session"
            result.append(
                SQLAlchemySessionFact(
                    call.module_id,
                    call,
                    call.ref,
                    call.ref.state,
                    kind,
                    kind.startswith("Async") or kind.startswith("async"),
                    call.provenance,
                    origin[0] if origin else None,
                    call.ref.symbol if origin else None,
                )
            )
        return tuple(sorted(result, key=lambda item: (item.module_id, item.call.location)))

    def _transactions(self, calls: tuple[CallFact, ...]) -> tuple[SQLAlchemyTransactionFact, ...]:
        result: list[SQLAlchemyTransactionFact] = []
        for call in calls:
            if not _sqlalchemy_name(call.ref, TX_NAMES):
                continue
            operation = next(
                name.rsplit(".", 1)[-1]
                for name in _names(call.ref)
                if name.rsplit(".", 1)[-1] in TX_NAMES
            )
            result.append(
                SQLAlchemyTransactionFact(
                    call.module_id,
                    call,
                    call.ref,
                    call.ref.state,
                    operation,
                    _is_async(call.ref),
                    call.provenance,
                )
            )
        return tuple(sorted(result, key=lambda item: (item.module_id, item.call.location)))

    def _queries(self, calls: tuple[CallFact, ...]) -> tuple[SQLAlchemyQueryFact, ...]:
        result: list[SQLAlchemyQueryFact] = []
        for call in calls:
            if not _sqlalchemy_name(call.ref, QUERY_NAMES):
                continue
            operation = next(
                name.rsplit(".", 1)[-1]
                for name in _names(call.ref)
                if name.rsplit(".", 1)[-1] in QUERY_NAMES
            )
            result.append(
                SQLAlchemyQueryFact(
                    call.module_id,
                    call,
                    call.ref,
                    call.ref.state,
                    operation,
                    _is_async(call.ref),
                    call.provenance,
                )
            )
        return tuple(sorted(result, key=lambda item: (item.module_id, item.call.location)))

    def _raw_sql(self, calls: tuple[CallFact, ...]) -> tuple[SQLAlchemyRawSQLFact, ...]:
        result: list[SQLAlchemyRawSQLFact] = []
        for call in calls:
            operation: str | None = None
            if _sqlalchemy_name(call.ref, frozenset({"text"})):
                operation = "text"
            elif _sqlalchemy_name(call.ref, frozenset({"exec_driver_sql"})):
                operation = "exec_driver_sql"
            elif _sqlalchemy_name(call.ref, frozenset({"execute"})):
                first = next((arg for arg in call.arguments if arg.position == 0), None)
                if first is not None and first.value.literal_kind == "str":
                    operation = "execute"
            if operation is None:
                continue
            first = next((arg for arg in call.arguments if arg.position == 0), None)
            argument = first.value if first is not None else None
            result.append(
                SQLAlchemyRawSQLFact(
                    call.module_id,
                    call,
                    call.ref,
                    call.ref.state,
                    operation,
                    call.provenance,
                    argument,
                    bool(argument and argument.literal_kind == "str"),
                    bool(argument and argument.is_dynamic_string),
                )
            )
        return tuple(sorted(result, key=lambda item: (item.module_id, item.call.location)))


SQLAlchemyConfidence = ResolutionState
SQLAlchemyColumnFact = SQLAlchemyMappedColumnFact
SQLAlchemySession = SQLAlchemySessionFact
SQLAlchemyTransaction = SQLAlchemyTransactionFact
SQLAlchemyQuery = SQLAlchemyQueryFact
SQLAlchemyRawSQL = SQLAlchemyRawSQLFact
