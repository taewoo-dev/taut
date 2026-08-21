"""Resolver-backed Pydantic construction and member operation extraction."""

from __future__ import annotations

from taut.analysis.framework.pydantic_facts import PydanticOperationFact
from taut.domain.facts import CallFact, ResolutionState, SymbolRef
from taut.domain.ids import ModuleId, SymbolId
from taut.domain.snapshot import AnalysisSnapshot

_OPERATIONS = frozenset(
    {"model_validate", "parse_obj", "from_orm", "model_construct", "model_dump", "dict"}
)


def extract_operations(
    snapshot: AnalysisSnapshot,
    calls: tuple[CallFact, ...],
    models: set[SymbolId],
    module_ids: frozenset[ModuleId] | None = None,
) -> tuple[PydanticOperationFact, ...]:
    result: list[PydanticOperationFact] = []
    models_by_value = {model.value: model for model in models}
    for call in calls:
        if module_ids is not None and call.module_id not in module_ids:
            continue
        operation = call.ref.written_name.rsplit(".", 1)[-1]
        selected_set: set[SymbolId] = set()
        refs = call.ref.candidates + ((call.ref.symbol,) if call.ref.symbol else ())
        for ref in refs:
            parts = ref.value.split(".")
            for end in range(1, len(parts) + 1):
                model = models_by_value.get(".".join(parts[:end]))
                if model is not None:
                    selected_set.add(model)
        selected = tuple(sorted(selected_set))
        uncertain = call.ref.state in (ResolutionState.AMBIGUOUS, ResolutionState.CONDITIONAL)
        model_ref: SymbolRef | None = None
        if len(selected) == 1 and not uncertain:
            model_ref = SymbolRef(
                call.ref.written_name.rsplit(".", 1)[0],
                ResolutionState.RESOLVED,
                selected[0],
                (),
                call.ref.provenance,
            )
        elif selected and uncertain:
            model_ref = SymbolRef(
                call.ref.written_name.rsplit(".", 1)[0],
                call.ref.state,
                None,
                selected,
                call.ref.provenance,
            )
        constructor = call.ref.symbol in models or (
            uncertain and bool(selected) and "." not in call.ref.written_name
        )
        if operation not in _OPERATIONS and not constructor:
            continue
        if constructor:
            operation, model_ref = "construct", call.ref
        if model_ref is None:
            continue
        result.append(
            PydanticOperationFact(
                call.module_id,
                operation,
                call,
                model_ref,
                None,
                call.arguments,
                call.ref.state
                if call.ref.state is not ResolutionState.RESOLVED
                else model_ref.state,
                call.provenance,
            )
        )
    return tuple(result)
