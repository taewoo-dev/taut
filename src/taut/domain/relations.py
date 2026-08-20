from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from taut.domain.facts import ImportEdge, SymbolRef, SyntaxContext
from taut.domain.ids import FactId, ModuleId, SymbolId
from taut.domain.location import SourceRange


class BindingKind(StrEnum):
    IMPORT = "import"
    DEFINITION = "definition"
    FIELD = "field"


@dataclass(frozen=True, order=True)
class Binding:
    id: FactId
    module_id: ModuleId
    local_name: str
    kind: BindingKind
    lexical_owner: SymbolId | None
    target: SymbolRef
    defining_fact_id: FactId
    location: SourceRange
    context: SyntaxContext

    def __post_init__(self) -> None:
        if not self.local_name.strip():
            raise ValueError("binding local name cannot be empty")
        if self.context.lexical_owner != self.lexical_owner:
            raise ValueError("binding owner must match its syntax context")


class UsePurpose(StrEnum):
    RUNTIME = "runtime"
    TYPE = "type"
    DECORATOR = "decorator"
    BASE = "base"
    DEFAULT = "default"
    ARGUMENT = "argument"
    METADATA = "metadata"


@dataclass(frozen=True, order=True)
class UseEdge:
    module_id: ModuleId
    occurrence_id: FactId
    ref: SymbolRef
    binding_id: FactId | None
    location: SourceRange
    context: SyntaxContext
    purpose: UsePurpose


@dataclass(frozen=True)
class ProjectRelations:
    bindings: tuple[Binding, ...]
    import_edges: tuple[ImportEdge, ...]
    use_edges: tuple[UseEdge, ...]

    def __post_init__(self) -> None:
        binding_ids = tuple(binding.id for binding in self.bindings)
        if len(binding_ids) != len(set(binding_ids)):
            raise ValueError("binding ids must be unique")
        use_ids = tuple(edge.occurrence_id for edge in self.use_edges)
        if len(use_ids) != len(set(use_ids)):
            raise ValueError("use occurrence ids must be unique")
        known_bindings = set(binding_ids)
        if any(edge.binding_id not in known_bindings for edge in self.use_edges if edge.binding_id):
            raise ValueError("use edges may only reference known bindings")
