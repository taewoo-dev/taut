from __future__ import annotations

from dataclasses import dataclass

from taut.domain.facts import (
    CallFact,
    ClassFact,
    ExpressionSummary,
    FieldFact,
    ResolutionState,
    SymbolRef,
)
from taut.domain.ids import ModuleId, SymbolId
from taut.domain.provenance import Provenance

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
MODEL_BASES = _MODEL_BASES
COLUMN_CALLS = _COLUMN_CALLS
RELATIONSHIP_CALL = _RELATIONSHIP_CALL
SESSION_FACTORIES = _SESSION_FACTORIES
SESSION_TYPES = _SESSION_TYPES
QUERY_NAMES = _QUERY_NAMES
TX_NAMES = _TX_NAMES

__all__ = [
    "SQLALCHEMY_MAPPED_COLUMNS",
    "SQLALCHEMY_MODELS",
    "SQLALCHEMY_PROVIDER_ID",
    "SQLALCHEMY_PROVIDER_VERSION",
    "SQLALCHEMY_QUERIES",
    "SQLALCHEMY_RAW_SQL",
    "SQLALCHEMY_RELATIONSHIPS",
    "SQLALCHEMY_SESSIONS",
    "SQLALCHEMY_TRANSACTIONS",
    "SQLAlchemyMappedColumnFact",
    "SQLAlchemyModelFact",
    "SQLAlchemyQueryFact",
    "SQLAlchemyRawSQLFact",
    "SQLAlchemyRelationshipFact",
    "SQLAlchemySessionFact",
    "SQLAlchemyTransactionFact",
]


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
    factory_ref: SymbolRef | None = None
    factory_symbol: SymbolId | None = None


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
    argument: ExpressionSummary | None = None
    is_literal: bool = False
    is_dynamic: bool = False
