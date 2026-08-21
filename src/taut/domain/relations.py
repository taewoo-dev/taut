from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from functools import cached_property
from types import MappingProxyType

from taut.domain.facts import ImportEdge, SymbolRef, SyntaxContext
from taut.domain.ids import FactId, ModuleId, SymbolId
from taut.domain.location import ProjectPath, SourceRange


class BindingKind(StrEnum):
    IMPORT = "import"
    DEFINITION = "definition"
    FIELD = "field"
    PARAMETER = "parameter"
    ASSIGNMENT = "assignment"
    LOOP = "loop"
    WITH_ITEM = "with_item"
    EXCEPTION = "exception"
    PATTERN = "pattern"
    COMPREHENSION = "comprehension"
    WALRUS = "walrus"


@dataclass(frozen=True, order=True)
class Binding:
    id: FactId
    module_id: ModuleId
    local_name: str
    kind: BindingKind
    lexical_owner: SymbolId | None
    target: SymbolRef
    defining_fact_id: FactId | None
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
    candidate_binding_ids: tuple[FactId, ...] = ()


@dataclass(frozen=True)
class ModuleRelations:
    bindings: tuple[Binding, ...] = ()
    use_edges: tuple[UseEdge, ...] = ()

    def __post_init__(self) -> None:
        if len(self.bindings) != len({binding.id for binding in self.bindings}):
            raise ValueError("module binding ids must be unique")
        if len(self.use_edges) != len({edge.occurrence_id for edge in self.use_edges}):
            raise ValueError("module use occurrence ids must be unique")
        if any(
            edge.binding_id is not None and edge.binding_id not in edge.candidate_binding_ids
            for edge in self.use_edges
        ):
            raise ValueError("selected binding must be one of the candidate bindings")
        if any(
            edge.candidate_binding_ids
            != tuple(sorted(set(edge.candidate_binding_ids), key=lambda item: item.value))
            for edge in self.use_edges
        ):
            raise ValueError("candidate binding ids must be sorted and unique")


@dataclass(frozen=True)
class ProjectRelations:
    bindings: tuple[Binding, ...]
    import_edges: tuple[ImportEdge, ...]
    use_edges: tuple[UseEdge, ...]

    def __post_init__(self) -> None:
        binding_by_id: dict[FactId, Binding] = {}
        for binding in self.bindings:
            if binding.id in binding_by_id:
                raise ValueError("binding ids must be unique")
            binding_by_id[binding.id] = binding
        use_ids: set[FactId] = set()
        for edge in self.use_edges:
            if edge.occurrence_id in use_ids:
                raise ValueError("use occurrence ids must be unique")
            use_ids.add(edge.occurrence_id)
            if edge.binding_id is not None:
                selected = binding_by_id.get(edge.binding_id)
                if selected is None:
                    raise ValueError("use edges may only reference known bindings")
                if selected.module_id != edge.module_id:
                    raise ValueError("use edges may only reference bindings in the same module")
            for candidate_id in edge.candidate_binding_ids:
                candidate = binding_by_id.get(candidate_id)
                if candidate is None:
                    raise ValueError("use edge candidates may only reference known bindings")
                if candidate.module_id != edge.module_id:
                    raise ValueError(
                        "use edge candidates may only reference bindings in the same module"
                    )
        object.__setattr__(self, "binding_by_id", MappingProxyType(binding_by_id))

    @cached_property
    def bindings_by_module(self) -> Mapping[ModuleId, tuple[Binding, ...]]:
        return MappingProxyType(_grouped(self.bindings, lambda item: item.module_id))

    @cached_property
    def binding_by_id(self) -> Mapping[FactId, Binding]:
        return MappingProxyType({binding.id: binding for binding in self.bindings})

    @cached_property
    def use_edges_by_module(self) -> Mapping[ModuleId, tuple[UseEdge, ...]]:
        return MappingProxyType(_grouped(self.use_edges, lambda item: item.module_id))

    @cached_property
    def use_edges_by_path_line(self) -> Mapping[tuple[ProjectPath, int], tuple[UseEdge, ...]]:
        return MappingProxyType(
            _grouped(
                self.use_edges,
                lambda item: (item.location.path, item.location.start_line),
            )
        )


def _grouped[K, V](items: tuple[V, ...], key: Callable[[V], K]) -> dict[K, tuple[V, ...]]:
    groups: dict[K, list[V]] = {}
    for item in items:
        group = key(item)
        groups.setdefault(group, []).append(item)
    return {group: tuple(values) for group, values in groups.items()}
