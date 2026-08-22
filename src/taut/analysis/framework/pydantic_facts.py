"""Typed capability values emitted by the first-party Pydantic provider."""

from __future__ import annotations

from dataclasses import dataclass

from taut.domain.facts import (
    CallArgument,
    CallFact,
    ClassFact,
    ExpressionSummary,
    FieldFact,
    ResolutionState,
    SymbolRef,
)
from taut.domain.ids import ModuleId, SymbolId
from taut.domain.provenance import Provenance

PYDANTIC_PROVIDER_ID = "taut.pydantic"
PYDANTIC_PROVIDER_VERSION = "1"
PYDANTIC_MODELS = "taut.pydantic.models@1"
PYDANTIC_FIELDS = "taut.pydantic.fields@1"
PYDANTIC_CONFIGS = "taut.pydantic.configs@1"
PYDANTIC_VALIDATORS = "taut.pydantic.validators@1"
PYDANTIC_SERIALIZERS = "taut.pydantic.serializers@1"
PYDANTIC_OPERATIONS = "taut.pydantic.operations@1"


@dataclass(frozen=True, order=True)
class PydanticModelFact:
    symbol: SymbolId
    module_id: ModuleId
    class_fact: ClassFact
    base_ref: SymbolRef
    base_refs: tuple[SymbolRef, ...]
    confidence: ResolutionState
    provenance: Provenance


@dataclass(frozen=True, order=True)
class PydanticFieldFact:
    model: SymbolId
    module_id: ModuleId
    field: FieldFact
    annotation_ref: SymbolRef | None
    declaration_ref: SymbolRef | None
    default: ExpressionSummary | None
    default_factory: ExpressionSummary | None
    alias: ExpressionSummary | None
    validation_alias: ExpressionSummary | None
    serialization_alias: ExpressionSummary | None
    confidence: ResolutionState
    provenance: Provenance

    @property
    def name(self) -> str:
        return self.field.name


@dataclass(frozen=True, order=True)
class PydanticConfigFact:
    model: SymbolId
    module_id: ModuleId
    kind: str
    field: FieldFact | None
    ref: SymbolRef
    options: tuple[tuple[str, ExpressionSummary], ...]
    confidence: ResolutionState
    provenance: Provenance


@dataclass(frozen=True, order=True)
class PydanticValidatorFact:
    model: SymbolId
    module_id: ModuleId
    function: SymbolId
    decorator: str
    decorator_ref: SymbolRef
    fields: tuple[str, ...]
    confidence: ResolutionState
    provenance: Provenance


@dataclass(frozen=True, order=True)
class PydanticSerializerFact:
    model: SymbolId
    module_id: ModuleId
    function: SymbolId
    decorator: str
    decorator_ref: SymbolRef
    fields: tuple[str, ...]
    confidence: ResolutionState
    provenance: Provenance


@dataclass(frozen=True, order=True)
class PydanticOperationFact:
    module_id: ModuleId
    operation: str
    call: CallFact
    model_ref: SymbolRef | None
    receiver_ref: SymbolRef | None
    arguments: tuple[CallArgument, ...]
    confidence: ResolutionState
    provenance: Provenance
