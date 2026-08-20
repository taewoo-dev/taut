"""Resolver-backed Pydantic construction and member operation extraction."""

from __future__ import annotations

from taut.analysis.framework.pydantic_facts import PydanticOperationFact
from taut.domain.facts import CallFact, ResolutionState, SymbolRef
from taut.domain.ids import SymbolId
from taut.domain.snapshot import AnalysisSnapshot

_OPERATIONS = frozenset(
    {"model_validate", "parse_obj", "from_orm", "model_construct", "model_dump", "dict"}
)


def extract_operations(
    snapshot: AnalysisSnapshot, calls: tuple[CallFact, ...], models: set[SymbolId]
) -> tuple[PydanticOperationFact, ...]:
    result: list[PydanticOperationFact] = []
    for call in calls:
        operation = call.ref.written_name.rsplit(".", 1)[-1]
        selected = tuple(
            model
            for model in models
            if (call.ref.symbol is not None and call.ref.symbol == model)
            or any(
                candidate == model or candidate.value.startswith(model.value + ".")
                for candidate in call.ref.candidates
            )
            or (call.ref.symbol is not None and call.ref.symbol.value.startswith(model.value + "."))
        )
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
