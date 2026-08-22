from __future__ import annotations

from taut.domain.facts import (
    CallFact,
    ClassFact,
    DecoratorFact,
    DefinitionFact,
    FieldFact,
    FunctionFact,
    ImportFact,
    ReferenceFact,
)

type ExtractedFact = (
    ImportFact
    | DefinitionFact
    | ReferenceFact
    | CallFact
    | DecoratorFact
    | FunctionFact
    | ClassFact
    | FieldFact
)


def fact_sort_key(value: ExtractedFact) -> tuple[str, int, int, str]:
    return (
        value.location.path.value,
        value.location.start_line,
        value.location.start_column,
        str(value.id),
    )
