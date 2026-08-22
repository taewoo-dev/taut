from __future__ import annotations

from taut.domain.facts import ModuleFacts, ResolutionState, SymbolRef, SyntaxPosition
from taut.domain.ids import FactId, SymbolId
from taut.domain.provenance import Provenance
from taut.domain.relations import Binding, BindingKind, ModuleRelations, UseEdge, UsePurpose


def emit_module_relations(
    facts: ModuleFacts,
    reference_binding_ids: dict[FactId, FactId | None],
    reference_candidate_binding_ids: dict[FactId, tuple[FactId, ...]],
) -> ModuleRelations:
    bindings = [
        Binding(
            item.id,
            item.module_id,
            item.local_name,
            BindingKind(item.kind),
            item.lexical_owner,
            _target(item.symbol_id, item.provenance),
            item.id,
            item.location,
            item.context,
        )
        for item in facts.bindings
    ]
    bindings.extend(
        Binding(
            item.id,
            item.module_id,
            item.alias
            or (
                item.imported_name.rsplit(".", 1)[-1]
                if item.is_from
                else item.imported_name.split(".", 1)[0]
            ),
            BindingKind.IMPORT,
            item.enclosing_symbol,
            _target(SymbolId(item.imported_name), item.provenance),
            item.id,
            item.location,
            item.context,
        )
        for item in facts.imports
    )
    bindings.extend(
        Binding(
            item.id,
            item.module_id,
            item.symbol_id.value.rsplit(".", 1)[-1],
            BindingKind.DEFINITION,
            item.enclosing_symbol,
            _target(item.symbol_id, item.provenance),
            item.id,
            item.location,
            item.context,
        )
        for item in facts.definitions
    )
    bindings.extend(
        Binding(
            item.id,
            item.module_id,
            item.name,
            BindingKind.FIELD,
            item.owner_symbol,
            _target(item.symbol_id, item.provenance),
            item.id,
            item.location,
            item.context,
        )
        for item in facts.fields
    )
    purposes = {
        SyntaxPosition.ANNOTATION: UsePurpose.TYPE,
        SyntaxPosition.DECORATOR: UsePurpose.DECORATOR,
        SyntaxPosition.BASE: UsePurpose.BASE,
        SyntaxPosition.DEFAULT: UsePurpose.DEFAULT,
        SyntaxPosition.ARGUMENT: UsePurpose.ARGUMENT,
        SyntaxPosition.METADATA: UsePurpose.METADATA,
    }
    uses = tuple(
        UseEdge(
            module_id=ref.module_id,
            occurrence_id=ref.id,
            ref=ref.ref,
            binding_id=reference_binding_ids.get(ref.id),
            location=ref.location,
            context=ref.context,
            purpose=purposes.get(ref.context.position, UsePurpose.RUNTIME),
            candidate_binding_ids=reference_candidate_binding_ids.get(ref.id, ()),
        )
        for ref in facts.references
    )
    return ModuleRelations(tuple(bindings), uses)


def _target(symbol: SymbolId, provenance: Provenance) -> SymbolRef:
    return SymbolRef(symbol.value, ResolutionState.RESOLVED, symbol, (), provenance)
