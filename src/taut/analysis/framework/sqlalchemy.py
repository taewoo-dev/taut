"""Resolver-owned SQLAlchemy semantic facts.

The provider deliberately consumes the language-neutral snapshot only.  In particular,
it never guesses a receiver from a local name or from a source line: call ownership is
established by the resolver's parent fact and source-range containment.
"""

from __future__ import annotations

from dataclasses import dataclass

from taut.analysis.providers import CapabilitySpec
from taut.domain.facts import (
    CallFact,
    ClassFact,
    FieldFact,
    ResolutionState,
    SymbolRef,
)
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, SymbolId
from taut.domain.location import SourceRange
from taut.domain.provenance import Provenance
from taut.domain.snapshot import AnalysisSnapshot

SQLALCHEMY_PROVIDER_ID = "taut.sqlalchemy"
SQLALCHEMY_PROVIDER_VERSION = "1"
SQLALCHEMY_MODELS = "taut.sqlalchemy.models@1"
SQLALCHEMY_MAPPED_COLUMNS = "taut.sqlalchemy.mapped_columns@1"
SQLALCHEMY_RELATIONSHIPS = "taut.sqlalchemy.relationships@1"
SQLALCHEMY_SESSIONS = "taut.sqlalchemy.sessions@1"
SQLALCHEMY_TRANSACTIONS = "taut.sqlalchemy.transactions@1"
SQLALCHEMY_QUERIES = "taut.sqlalchemy.queries@1"
SQLALCHEMY_RAW_SQL = "taut.sqlalchemy.raw_sql@1"

_MODEL_BASES = frozenset(
    {
        "sqlalchemy.orm.DeclarativeBase",
        "sqlalchemy.orm.declarative_base",
        "sqlalchemy.ext.declarative.declarative_base",
    }
)
_COLUMN_CALLS = frozenset({"sqlalchemy.orm.mapped_column", "sqlalchemy.Column"})
_RELATIONSHIP_CALL = "sqlalchemy.orm.relationship"
_SESSION_TYPES = frozenset({"sqlalchemy.orm.Session", "sqlalchemy.ext.asyncio.AsyncSession"})
_SESSION_FACTORIES = frozenset(
    {
        "sqlalchemy.orm.sessionmaker",
        "sqlalchemy.orm.scoped_session",
        "sqlalchemy.ext.asyncio.async_sessionmaker",
        "sqlalchemy.ext.asyncio.async_scoped_session",
    }
)
_QUERY_NAMES = frozenset({"select", "query", "execute", "scalars"})
_TX_NAMES = frozenset({"begin", "commit", "rollback"})


@dataclass(frozen=True, order=True)
class SQLAlchemyModelFact:
    symbol: SymbolId
    module_id: ModuleId
    class_fact: ClassFact
    base_refs: tuple[SymbolRef, ...]
    model_ref: SymbolRef
    confidence: ResolutionState
    provenance: Provenance


@dataclass(frozen=True, order=True)
class SQLAlchemyMappedColumnFact:
    model: SymbolId
    module_id: ModuleId
    field: FieldFact
    call: CallFact | None
    ref: SymbolRef
    confidence: ResolutionState
    provenance: Provenance

    @property
    def name(self) -> str:
        return self.field.name


@dataclass(frozen=True, order=True)
class SQLAlchemyRelationshipFact:
    model: SymbolId
    module_id: ModuleId
    field: FieldFact
    call: CallFact | None
    ref: SymbolRef
    confidence: ResolutionState
    provenance: Provenance

    @property
    def name(self) -> str:
        return self.field.name


@dataclass(frozen=True, order=True)
class SQLAlchemySessionFact:
    module_id: ModuleId
    call: CallFact
    ref: SymbolRef
    confidence: ResolutionState
    kind: str
    is_async: bool
    provenance: Provenance


@dataclass(frozen=True, order=True)
class SQLAlchemyTransactionFact:
    module_id: ModuleId
    call: CallFact
    ref: SymbolRef
    confidence: ResolutionState
    operation: str
    is_async: bool
    provenance: Provenance


@dataclass(frozen=True, order=True)
class SQLAlchemyQueryFact:
    module_id: ModuleId
    call: CallFact
    ref: SymbolRef
    confidence: ResolutionState
    operation: str
    is_async: bool
    provenance: Provenance


@dataclass(frozen=True, order=True)
class SQLAlchemyRawSQLFact:
    module_id: ModuleId
    call: CallFact
    ref: SymbolRef
    confidence: ResolutionState
    operation: str
    provenance: Provenance


def _contains(outer: SourceRange, inner: SourceRange) -> bool:
    if outer.path != inner.path:
        return False
    return (outer.start_line, outer.start_column) <= (inner.start_line, inner.start_column) and (
        inner.end_line,
        inner.end_column,
    ) <= (outer.end_line, outer.end_column)


def _state(ref: SymbolRef) -> ResolutionState:
    return ref.state


def _names(ref: SymbolRef) -> frozenset[str]:
    values = {ref.symbol.value} if ref.symbol is not None else set()
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
        sessions = self._sessions(calls)
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
                and _contains(binding.location, call.location)
                for call in calls
            )
            if binding.target.symbol is not None
        }
        direct_bases = {SymbolId(value) for value in _MODEL_BASES} | declarative_bases
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
            # parent_fact_id is the primary join; containment handles adapters that do not
            # attach a parent to assignment calls while still preventing nested leakage.
            nested = tuple(
                call
                for call in calls
                if call.module_id == field.module_id
                and _contains(field.location, call.location)
                and (call.context.parent_fact_id == field.id or call.context.parent_fact_id is None)
            )
            for call in nested:
                if call.ref.symbol in {SymbolId(value) for value in _COLUMN_CALLS} or _names(
                    call.ref
                ).intersection(_COLUMN_CALLS):
                    columns.append(
                        SQLAlchemyMappedColumnFact(
                            field.owner_symbol,
                            field.module_id,
                            field,
                            call,
                            call.ref,
                            _state(call.ref),
                            call.provenance,
                        )
                    )
                if call.ref.symbol == SymbolId(_RELATIONSHIP_CALL) or _RELATIONSHIP_CALL in _names(
                    call.ref
                ):
                    relationships.append(
                        SQLAlchemyRelationshipFact(
                            field.owner_symbol,
                            field.module_id,
                            field,
                            call,
                            call.ref,
                            _state(call.ref),
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

    def _sessions(self, calls: tuple[CallFact, ...]) -> tuple[SQLAlchemySessionFact, ...]:
        result = []
        for call in calls:
            names = _names(call.ref)
            kind = next(
                (
                    name.rsplit(".", 1)[-1]
                    for name in names
                    if name in _SESSION_TYPES | _SESSION_FACTORIES
                ),
                None,
            )
            if kind is None:
                continue
            result.append(
                SQLAlchemySessionFact(
                    call.module_id,
                    call,
                    call.ref,
                    _state(call.ref),
                    kind,
                    kind.startswith("Async") or kind.startswith("async"),
                    call.provenance,
                )
            )
        return tuple(sorted(result, key=lambda item: (item.module_id, item.call.location)))

    def _transactions(self, calls: tuple[CallFact, ...]) -> tuple[SQLAlchemyTransactionFact, ...]:
        result = []
        for call in calls:
            if not _sqlalchemy_name(call.ref, _TX_NAMES):
                continue
            operation = next(
                name.rsplit(".", 1)[-1]
                for name in _names(call.ref)
                if name.rsplit(".", 1)[-1] in _TX_NAMES
            )
            result.append(
                SQLAlchemyTransactionFact(
                    call.module_id,
                    call,
                    call.ref,
                    _state(call.ref),
                    operation,
                    _is_async(call.ref),
                    call.provenance,
                )
            )
        return tuple(sorted(result, key=lambda item: (item.module_id, item.call.location)))

    def _queries(self, calls: tuple[CallFact, ...]) -> tuple[SQLAlchemyQueryFact, ...]:
        result = []
        for call in calls:
            if not _sqlalchemy_name(call.ref, _QUERY_NAMES):
                continue
            operation = next(
                name.rsplit(".", 1)[-1]
                for name in _names(call.ref)
                if name.rsplit(".", 1)[-1] in _QUERY_NAMES
            )
            result.append(
                SQLAlchemyQueryFact(
                    call.module_id,
                    call,
                    call.ref,
                    _state(call.ref),
                    operation,
                    _is_async(call.ref),
                    call.provenance,
                )
            )
        return tuple(sorted(result, key=lambda item: (item.module_id, item.call.location)))

    def _raw_sql(self, calls: tuple[CallFact, ...]) -> tuple[SQLAlchemyRawSQLFact, ...]:
        result = []
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
            result.append(
                SQLAlchemyRawSQLFact(
                    call.module_id, call, call.ref, _state(call.ref), operation, call.provenance
                )
            )
        return tuple(sorted(result, key=lambda item: (item.module_id, item.call.location)))


# Short aliases make the provider convenient for integrations while preserving the
# explicit names used in capability payloads.
SQLAlchemyConfidence = ResolutionState
SQLAlchemyColumnFact = SQLAlchemyMappedColumnFact
SQLAlchemySession = SQLAlchemySessionFact
SQLAlchemyTransaction = SQLAlchemyTransactionFact
SQLAlchemyQuery = SQLAlchemyQueryFact
SQLAlchemyRawSQL = SQLAlchemyRawSQLFact
