from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import cast

from taut.analysis.framework.indexes import grouped
from taut.analysis.framework.pydantic_facts import (
    PYDANTIC_CONFIGS,
    PYDANTIC_FIELDS,
    PYDANTIC_MODELS,
    PYDANTIC_OPERATIONS,
    PYDANTIC_SERIALIZERS,
    PYDANTIC_VALIDATORS,
    PydanticConfigFact,
    PydanticFieldFact,
    PydanticModelFact,
    PydanticOperationFact,
    PydanticSerializerFact,
    PydanticValidatorFact,
)
from taut.analysis.framework.pydantic_operations import extract_operations
from taut.domain.facts import CallFact, ClassFact, FieldFact
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, SymbolId
from taut.domain.location import SourceRange
from taut.domain.relations import UseEdge
from taut.domain.snapshot import AnalysisSnapshot

_Decorated = PydanticSerializerFact | PydanticValidatorFact


def analyze_incremental_pydantic(
    snapshot: AnalysisSnapshot,
    previous: FrozenMap[str, tuple[object, ...]],
    impacted: frozenset[ModuleId],
    *,
    models_from: Callable[
        [AnalysisSnapshot, tuple[ClassFact, ...], frozenset[SymbolId]],
        tuple[PydanticModelFact, ...],
    ],
    fields_from: Callable[
        [
            AnalysisSnapshot,
            tuple[FieldFact, ...],
            dict[ModuleId, tuple[CallFact, ...]],
            Mapping[ModuleId, tuple[UseEdge, ...]],
            set[SymbolId],
        ],
        tuple[PydanticFieldFact, ...],
    ],
    configs_from: Callable[
        [
            AnalysisSnapshot,
            tuple[ClassFact, ...],
            tuple[FieldFact, ...],
            dict[ModuleId, tuple[CallFact, ...]],
            Mapping[ModuleId, tuple[UseEdge, ...]],
            set[SymbolId],
        ],
        tuple[PydanticConfigFact, ...],
    ],
    decorated_from: Callable[
        [AnalysisSnapshot, tuple[PydanticModelFact, ...], bool, frozenset[ModuleId] | None],
        tuple[_Decorated, ...],
    ],
) -> FrozenMap[str, tuple[object, ...]]:
    if not impacted:
        return FrozenMap(previous.items())
    selected = tuple(
        snapshot.modules[module_id]
        for module_id in sorted(impacted)
        if module_id in snapshot.modules
    )
    classes = tuple(item for module in selected for item in module.classes)
    fields = tuple(item for module in selected for item in module.fields)
    calls = tuple(item for module in selected for item in module.calls)
    old_models = cast(tuple[PydanticModelFact, ...], previous.get(PYDANTIC_MODELS, ()))
    inherited = frozenset(item.symbol for item in old_models if item.module_id not in impacted)
    fresh_models = models_from(snapshot, classes, inherited)
    models = _merge_models(old_models, fresh_models, impacted)
    model_ids = {item.symbol for item in models}
    calls_by_module = dict(grouped(calls, lambda item: item.module_id))
    edges_by_module = snapshot.relations.use_edges_by_module
    fresh_fields = fields_from(snapshot, fields, calls_by_module, edges_by_module, model_ids)
    fresh_configs = configs_from(
        snapshot, classes, fields, calls_by_module, edges_by_module, model_ids
    )
    fresh_validators = cast(
        tuple[PydanticValidatorFact, ...],
        decorated_from(snapshot, models, False, impacted),
    )
    fresh_serializers = cast(
        tuple[PydanticSerializerFact, ...],
        decorated_from(snapshot, models, True, impacted),
    )
    return FrozenMap(
        (
            (PYDANTIC_MODELS, models),
            (PYDANTIC_FIELDS, _merge_fields(previous, fresh_fields, impacted)),
            (PYDANTIC_CONFIGS, _merge_configs(previous, fresh_configs, impacted)),
            (
                PYDANTIC_VALIDATORS,
                _merge_validators(previous, fresh_validators, impacted),
            ),
            (
                PYDANTIC_SERIALIZERS,
                _merge_serializers(previous, fresh_serializers, impacted),
            ),
            (
                PYDANTIC_OPERATIONS,
                _merge_operations(
                    previous,
                    extract_operations(snapshot, calls, model_ids),
                    impacted,
                ),
            ),
        )
    )


def _merge_models(
    old: tuple[PydanticModelFact, ...],
    fresh: tuple[PydanticModelFact, ...],
    impacted: frozenset[ModuleId],
) -> tuple[PydanticModelFact, ...]:
    kept = tuple(item for item in old if item.module_id not in impacted)
    return tuple(
        sorted(
            (*kept, *fresh),
            key=lambda item: (item.module_id, item.class_fact.location, item.symbol),
        )
    )


def _merge_fields(
    previous: FrozenMap[str, tuple[object, ...]],
    fresh: tuple[PydanticFieldFact, ...],
    impacted: frozenset[ModuleId],
) -> tuple[PydanticFieldFact, ...]:
    old = cast(tuple[PydanticFieldFact, ...], previous.get(PYDANTIC_FIELDS, ()))
    kept = tuple(item for item in old if item.module_id not in impacted)
    return tuple(sorted((*kept, *fresh), key=lambda item: (item.module_id, item.field.location)))


def _merge_configs(
    previous: FrozenMap[str, tuple[object, ...]],
    fresh: tuple[PydanticConfigFact, ...],
    impacted: frozenset[ModuleId],
) -> tuple[PydanticConfigFact, ...]:
    old = cast(tuple[PydanticConfigFact, ...], previous.get(PYDANTIC_CONFIGS, ()))
    kept = tuple(item for item in old if item.module_id not in impacted)
    return tuple(sorted((*kept, *fresh), key=_config_key))


def _config_key(item: PydanticConfigFact) -> tuple[object, ...]:
    location = item.field.location if item.field is not None else item.ref.provenance.location
    return (0 if item.kind == "v2" else 1, item.module_id, *_location_key(location))


def _merge_validators(
    previous: FrozenMap[str, tuple[object, ...]],
    fresh: tuple[PydanticValidatorFact, ...],
    impacted: frozenset[ModuleId],
) -> tuple[PydanticValidatorFact, ...]:
    old = cast(tuple[PydanticValidatorFact, ...], previous.get(PYDANTIC_VALIDATORS, ()))
    kept = tuple(item for item in old if item.module_id not in impacted)
    return tuple(sorted((*kept, *fresh), key=_decorated_key))


def _merge_serializers(
    previous: FrozenMap[str, tuple[object, ...]],
    fresh: tuple[PydanticSerializerFact, ...],
    impacted: frozenset[ModuleId],
) -> tuple[PydanticSerializerFact, ...]:
    old = cast(tuple[PydanticSerializerFact, ...], previous.get(PYDANTIC_SERIALIZERS, ()))
    kept = tuple(item for item in old if item.module_id not in impacted)
    return tuple(sorted((*kept, *fresh), key=_decorated_key))


def _decorated_key(item: _Decorated) -> tuple[object, ...]:
    return (item.module_id, *_location_key(item.decorator_ref.provenance.location), item.function)


def _merge_operations(
    previous: FrozenMap[str, tuple[object, ...]],
    fresh: tuple[PydanticOperationFact, ...],
    impacted: frozenset[ModuleId],
) -> tuple[PydanticOperationFact, ...]:
    old = cast(tuple[PydanticOperationFact, ...], previous.get(PYDANTIC_OPERATIONS, ()))
    kept = tuple(item for item in old if item.module_id not in impacted)
    return tuple(sorted((*kept, *fresh), key=lambda item: (item.module_id, item.call.location)))


def _location_key(location: SourceRange | None) -> tuple[object, ...]:
    if location is None:
        return ("", 0, 0, 0, 0)
    return (
        location.path.value,
        location.start_line,
        location.start_column,
        location.end_line,
        location.end_column,
    )
