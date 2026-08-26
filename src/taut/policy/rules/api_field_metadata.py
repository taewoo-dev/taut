from __future__ import annotations

from taut.domain.facts import CallFact, ClassFact, FieldFact
from taut.domain.location import SourceRange

_BASE_MODELS = frozenset({"pydantic.BaseModel", "pydantic.main.BaseModel"})
_FIELD_CALLS = frozenset({"pydantic.Field", "pydantic.fields.Field"})


def is_base_model(class_fact: ClassFact) -> bool:
    return any(symbol.value in _BASE_MODELS for base in class_fact.bases for symbol in base.symbols)


def field_metadata_names(
    field: FieldFact, calls: tuple[CallFact, ...]
) -> frozenset[str | None] | None:
    nested = next(
        (
            call
            for call in calls
            if call.enclosing_symbol == field.owner_symbol
            and call.ref.symbol is not None
            and call.ref.symbol.value in _FIELD_CALLS
            and _range_contains(field.location, call.location)
        ),
        None,
    )
    if nested is not None:
        return frozenset(argument.name for argument in nested.arguments)
    if field.value is None or not any(
        symbol.value in _FIELD_CALLS for symbol in field.value.symbols
    ):
        return None
    return frozenset(argument.name for argument in field.value.arguments)


def _range_contains(outer: SourceRange, inner: SourceRange) -> bool:
    return (
        outer.path == inner.path
        and (outer.start_line, outer.start_column) <= (inner.start_line, inner.start_column)
        and (inner.end_line, inner.end_column) <= (outer.end_line, outer.end_column)
    )
