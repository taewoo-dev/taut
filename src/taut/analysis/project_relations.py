from __future__ import annotations

import hashlib
from dataclasses import replace

from taut.domain.facts import (
    ImportFact,
    ModuleFacts,
    ProjectIndex,
    ResolutionState,
    SymbolRef,
    ScopeKind,
    SyntaxPosition,
)
from taut.domain.frozen import FrozenMap
from taut.domain.ids import FactId, ModuleId, SymbolId
from taut.domain.relations import (
    Binding,
    BindingKind,
    ModuleRelations,
    ProjectRelations,
    UseEdge,
    UsePurpose,
)


def build_project_relations(
    modules: FrozenMap[ModuleId, ModuleFacts],
    project: ProjectIndex,
    module_relations: tuple[ModuleRelations, ...] = (),
) -> ProjectRelations:
    derived = tuple(
        sorted(
            (binding for facts in modules.values() for binding in _module_bindings(facts)),
            key=lambda item: (
                item.location.path.value,
                item.location.start_line,
                item.location.start_column,
                item.id.value,
            ),
        )
    )
    supplied = tuple(binding for relations in module_relations for binding in relations.bindings)
    bindings = tuple(
        sorted(
            (*derived, *supplied),
            key=lambda item: (
                item.location.path.value,
                item.location.start_line,
                item.location.start_column,
                item.id.value,
            ),
        )
    )
    bindings_by_module = {
        module_id: tuple(binding for binding in bindings if binding.module_id == module_id)
        for module_id in modules
    }
    derived_uses = tuple(
        UseEdge(
            module_id=reference.module_id,
            occurrence_id=reference.id,
            ref=reference.ref,
            binding_id=_matching_binding(
                reference.ref,
                reference.enclosing_symbol,
                bindings_by_module[reference.module_id],
            ),
            location=reference.location,
            context=reference.context,
            purpose=_purpose(reference.context.position),
        )
        for facts in modules.values()
        for reference in facts.references
    )
    supplied_uses = tuple(edge for relations in module_relations for edge in relations.use_edges)
    use_edges = tuple(
        sorted((*derived_uses, *supplied_uses), key=lambda item: item.occurrence_id.value)
    )
    return ProjectRelations(bindings, project.import_edges, use_edges)


def _module_bindings(facts: ModuleFacts) -> tuple[Binding, ...]:
    values: list[Binding] = []
    for import_fact in facts.imports:
        local_name = _import_local_name(import_fact)
        values.append(
            Binding(
                id=import_fact.id,
                module_id=import_fact.module_id,
                local_name=local_name,
                kind=BindingKind.IMPORT,
                lexical_owner=import_fact.enclosing_symbol,
                target=_resolved_target(import_fact.imported_name, import_fact),
                defining_fact_id=import_fact.id,
                location=import_fact.location,
                context=import_fact.context,
            )
        )
    for definition in facts.definitions:
        values.append(
            Binding(
                id=definition.id,
                module_id=definition.module_id,
                local_name=definition.symbol_id.value.rsplit(".", 1)[-1],
                kind=BindingKind.DEFINITION,
                lexical_owner=definition.enclosing_symbol,
                target=SymbolRef(
                    definition.symbol_id.value,
                    ResolutionState.RESOLVED,
                    definition.symbol_id,
                    (),
                    definition.provenance,
                ),
                defining_fact_id=definition.id,
                location=definition.location,
                context=definition.context,
            )
        )
    for field in facts.fields:
        values.append(
            Binding(
                id=field.id,
                module_id=field.module_id,
                local_name=field.name,
                kind=BindingKind.FIELD,
                lexical_owner=field.owner_symbol,
                target=SymbolRef(
                    field.symbol_id.value,
                    ResolutionState.RESOLVED,
                    field.symbol_id,
                    (),
                    field.provenance,
                ),
                defining_fact_id=field.id,
                location=field.location,
                context=field.context,
            )
        )
    for function in facts.functions:
        for parameter in function.parameters:
            symbol = SymbolId(f"{function.symbol_id.value}.{parameter.name}")
            raw = f"{facts.module.id.value}:parameter:{symbol.value}"
            values.append(
                Binding(
                    id=FactId(hashlib.sha256(raw.encode()).hexdigest()),
                    module_id=facts.module.id,
                    local_name=parameter.name,
                    kind=BindingKind.PARAMETER,
                    lexical_owner=function.symbol_id,
                    target=SymbolRef(
                        symbol.value,
                        ResolutionState.RESOLVED,
                        symbol,
                        (),
                        function.provenance,
                    ),
                    defining_fact_id=None,
                    location=function.location,
                    context=replace(
                        function.context,
                        lexical_owner=function.symbol_id,
                        scope_kind=ScopeKind.FUNCTION,
                    ),
                )
            )
    return tuple(values)


def _resolved_target(name: str, fact: ImportFact) -> SymbolRef:
    symbol = SymbolId(name)
    return SymbolRef(name, ResolutionState.RESOLVED, symbol, (), fact.provenance)


def _import_local_name(fact: ImportFact) -> str:
    if fact.alias:
        return fact.alias
    if fact.is_from:
        return fact.imported_name.rsplit(".", 1)[-1]
    return fact.imported_name.split(".", 1)[0]


def _matching_binding(
    ref: SymbolRef,
    owner: SymbolId | None,
    bindings: tuple[Binding, ...],
) -> FactId | None:
    if ref.state not in (ResolutionState.RESOLVED, ResolutionState.CONDITIONAL):
        return None
    local_name = ref.written_name.split(".", 1)[0]
    candidates = [binding for binding in bindings if binding.local_name == local_name]
    if not candidates:
        return None
    candidates.sort(
        key=lambda binding: (
            0 if binding.lexical_owner == owner else 1 if binding.lexical_owner is None else 2,
            binding.location.start_line,
            binding.id.value,
        )
    )
    return candidates[0].id


def _purpose(position: SyntaxPosition) -> UsePurpose:
    return {
        SyntaxPosition.ANNOTATION: UsePurpose.TYPE,
        SyntaxPosition.DECORATOR: UsePurpose.DECORATOR,
        SyntaxPosition.BASE: UsePurpose.BASE,
        SyntaxPosition.DEFAULT: UsePurpose.DEFAULT,
        SyntaxPosition.ARGUMENT: UsePurpose.ARGUMENT,
        SyntaxPosition.METADATA: UsePurpose.METADATA,
    }.get(position, UsePurpose.RUNTIME)
