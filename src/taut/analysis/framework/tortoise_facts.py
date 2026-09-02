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

TORTOISE_PROVIDER_ID = "taut.tortoise"
TORTOISE_PROVIDER_VERSION = "2"
TORTOISE_MODELS = "taut.tortoise.models@1"
TORTOISE_FIELDS = "taut.tortoise.fields@1"
TORTOISE_RELATIONSHIPS = "taut.tortoise.relationships@1"
TORTOISE_CONNECTIONS = "taut.tortoise.connections@1"
TORTOISE_TRANSACTIONS = "taut.tortoise.transactions@1"
TORTOISE_QUERIES = "taut.tortoise.queries@1"
TORTOISE_RAW_SQL = "taut.tortoise.raw_sql@1"


@dataclass(frozen=True, order=True)
class TortoiseModelFact:
    symbol: SymbolId
    module_id: ModuleId
    class_fact: ClassFact
    base_refs: tuple[SymbolRef, ...]
    model_ref: SymbolRef
    confidence: ResolutionState
    provenance: Provenance


@dataclass(frozen=True, order=True)
class TortoiseFieldFact:
    model: SymbolId
    module_id: ModuleId
    field: FieldFact
    call: CallFact
    ref: SymbolRef
    confidence: ResolutionState
    provenance: Provenance

    @property
    def name(self) -> str:
        return self.field.name


@dataclass(frozen=True, order=True)
class TortoiseRelationshipFact:
    model: SymbolId
    module_id: ModuleId
    field: FieldFact
    call: CallFact
    ref: SymbolRef
    confidence: ResolutionState
    provenance: Provenance

    @property
    def name(self) -> str:
        return self.field.name


@dataclass(frozen=True, order=True)
class TortoiseConnectionFact:
    module_id: ModuleId
    call: CallFact
    ref: SymbolRef
    confidence: ResolutionState
    operation: str
    provenance: Provenance


@dataclass(frozen=True, order=True)
class TortoiseTransactionFact:
    module_id: ModuleId
    call: CallFact
    ref: SymbolRef
    confidence: ResolutionState
    operation: str
    provenance: Provenance


@dataclass(frozen=True, order=True)
class TortoiseQueryFact:
    module_id: ModuleId
    call: CallFact
    ref: SymbolRef
    confidence: ResolutionState
    operation: str
    is_write: bool
    provenance: Provenance


@dataclass(frozen=True, order=True)
class TortoiseRawSQLFact:
    module_id: ModuleId
    call: CallFact
    ref: SymbolRef
    confidence: ResolutionState
    operation: str
    provenance: Provenance
    argument: ExpressionSummary | None = None
    is_literal: bool = False
    is_dynamic: bool = False
