"""Resolver-only semantic extraction for Pydantic v1 and v2."""

from __future__ import annotations

from taut.analysis.framework.indexes import grouped
from taut.analysis.framework.pydantic_facts import (
    PYDANTIC_CONFIGS,
    PYDANTIC_FIELDS,
    PYDANTIC_MODELS,
    PYDANTIC_OPERATIONS,
    PYDANTIC_PROVIDER_ID,
    PYDANTIC_PROVIDER_VERSION,
    PYDANTIC_SERIALIZERS,
    PYDANTIC_VALIDATORS,
    PydanticConfigFact,
    PydanticFieldFact,
    PydanticModelFact,
    PydanticOperationFact,
    PydanticSerializerFact,
    PydanticValidatorFact,
)
from taut.analysis.framework.pydantic_incremental import analyze_incremental_pydantic
from taut.analysis.framework.pydantic_models import extract_pydantic_models
from taut.analysis.framework.pydantic_operations import extract_operations
from taut.analysis.providers import CapabilitySpec
from taut.domain.facts import (
    CallFact,
    ClassFact,
    ExpressionSummary,
    FieldFact,
    ResolutionState,
    SymbolRef,
)
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, SymbolId
from taut.domain.location import SourceRange
from taut.domain.relations import UseEdge
from taut.domain.snapshot import AnalysisSnapshot

__all__ = [
    "PYDANTIC_CONFIGS",
    "PYDANTIC_FIELDS",
    "PYDANTIC_MODELS",
    "PYDANTIC_OPERATIONS",
    "PYDANTIC_PROVIDER_ID",
    "PYDANTIC_PROVIDER_VERSION",
    "PYDANTIC_SERIALIZERS",
    "PYDANTIC_VALIDATORS",
    "PydanticConfigFact",
    "PydanticFieldFact",
    "PydanticModelFact",
    "PydanticOperationFact",
    "PydanticProvider",
    "PydanticSerializerFact",
    "PydanticValidatorFact",
]

_BASES = frozenset({"pydantic.BaseModel", "pydantic.v1.BaseModel"})
_FIELD = frozenset({"pydantic.Field", "pydantic.fields.Field"})
_CONFIG = frozenset({"pydantic.ConfigDict", "pydantic.v1.BaseConfig"})
_VALIDATORS = frozenset(
    {
        "pydantic.validator",
        "pydantic.root_validator",
        "pydantic.field_validator",
        "pydantic.model_validator",
        "pydantic.functional_validators.field_validator",
        "pydantic.class_validators.validator",
        "pydantic.class_validators.root_validator",
    }
)
_SERIALIZERS = frozenset(
    {"pydantic.computed_field", "pydantic.field_serializer", "pydantic.model_serializer"}
)
_OPERATIONS = frozenset(
    {
        "model_validate",
        "parse_obj",
        "from_orm",
        "model_construct",
        "model_dump",
        "dict",
    }
)
_BASE_SYMBOLS = frozenset(SymbolId(value) for value in _BASES)
_FIELD_SYMBOLS = frozenset(SymbolId(value) for value in _FIELD)
_CONFIG_SYMBOLS = frozenset(SymbolId(value) for value in _CONFIG)


def _contains(outer: SourceRange, inner: SourceRange) -> bool:
    return (
        outer.path == inner.path
        and (outer.start_line, outer.start_column) <= (inner.start_line, inner.start_column)
        and (inner.end_line, inner.end_column) <= (outer.end_line, outer.end_column)
    )


def _calls(snapshot: AnalysisSnapshot) -> tuple[CallFact, ...]:
    return tuple(call for module in snapshot.modules.values() for call in module.calls)


def _refs(
    snapshot: AnalysisSnapshot,
    module_id: ModuleId,
    location: SourceRange,
    edges: tuple[UseEdge, ...] | None = None,
) -> tuple[SymbolRef, ...]:
    return tuple(
        edge.ref
        for edge in (snapshot.relations.use_edges if edges is None else edges)
        if edge.module_id == module_id and _contains(location, edge.location)
    )


def _argument(
    call: CallFact | None, name: str, position: int | None = None
) -> ExpressionSummary | None:
    if call is None:
        return None
    item = next((arg for arg in call.arguments if arg.name == name), None)
    if item is None and position is not None:
        item = next((arg for arg in call.arguments if arg.position == position), None)
    return item.value if item else None


def _matches(ref: SymbolRef, values: frozenset[str]) -> bool:
    return (ref.symbol is not None and ref.symbol.value in values) or any(
        candidate.value in values for candidate in ref.candidates
    )


class PydanticProvider:
    """Extract Pydantic semantics from an :class:`AnalysisSnapshot` only."""

    id = PYDANTIC_PROVIDER_ID
    version = PYDANTIC_PROVIDER_VERSION
    provides = frozenset(
        CapabilitySpec(value)
        for value in (
            PYDANTIC_MODELS,
            PYDANTIC_FIELDS,
            PYDANTIC_CONFIGS,
            PYDANTIC_VALIDATORS,
            PYDANTIC_SERIALIZERS,
            PYDANTIC_OPERATIONS,
        )
    )

    def analyze(self, snapshot: AnalysisSnapshot) -> FrozenMap[str, tuple[object, ...]]:
        classes = tuple(item for module in snapshot.modules.values() for item in module.classes)
        fields = tuple(item for module in snapshot.modules.values() for item in module.fields)
        calls = _calls(snapshot)
        calls_by_module = dict(grouped(calls, lambda item: item.module_id))
        edges_by_module = dict(grouped(snapshot.relations.use_edges, lambda item: item.module_id))
        models = self._models(snapshot, classes)
        model_ids = {item.symbol for item in models}
        return FrozenMap(
            (
                (PYDANTIC_MODELS, models),
                (
                    PYDANTIC_FIELDS,
                    self._fields(snapshot, fields, calls_by_module, edges_by_module, model_ids),
                ),
                (
                    PYDANTIC_CONFIGS,
                    self._configs(
                        snapshot, classes, fields, calls_by_module, edges_by_module, model_ids
                    ),
                ),
                (PYDANTIC_VALIDATORS, self._decorated(snapshot, models, False)),
                (PYDANTIC_SERIALIZERS, self._decorated(snapshot, models, True)),
                (PYDANTIC_OPERATIONS, extract_operations(snapshot, calls, model_ids)),
            )
        )

    def analyze_incremental(
        self,
        snapshot: AnalysisSnapshot,
        previous: FrozenMap[str, tuple[object, ...]],
        impacted: frozenset[ModuleId],
    ) -> FrozenMap[str, tuple[object, ...]]:
        return analyze_incremental_pydantic(
            snapshot,
            previous,
            impacted,
            models_from=self._models,
            fields_from=self._fields,
            configs_from=self._configs,
            decorated_from=self._decorated,
        )

    def _base_ref(
        self,
        snapshot: AnalysisSnapshot,
        item: ClassFact,
        written: str,
        symbols: tuple[SymbolId, ...],
        base_edges: dict[tuple[ModuleId, str], tuple[UseEdge, ...]],
    ) -> SymbolRef:
        candidates = tuple(sorted(set(symbols)))
        edge = next(
            (
                edge
                for edge in base_edges.get((item.module_id, written), ())
                if _contains(item.location, edge.location)
            ),
            None,
        )
        if edge:
            return edge.ref
        return SymbolRef(
            written,
            ResolutionState.RESOLVED
            if len(candidates) == 1
            else (ResolutionState.AMBIGUOUS if len(candidates) > 1 else ResolutionState.UNRESOLVED),
            candidates[0] if len(candidates) == 1 else None,
            candidates if len(candidates) > 1 else (),
            item.provenance,
        )

    def _models(
        self,
        snapshot: AnalysisSnapshot,
        classes: tuple[ClassFact, ...],
        inherited_models: frozenset[SymbolId] = frozenset(),
    ) -> tuple[PydanticModelFact, ...]:
        return extract_pydantic_models(
            snapshot,
            classes,
            inherited_models,
            _BASE_SYMBOLS,
            self._base_ref,
        )

    def _fields(
        self,
        snapshot: AnalysisSnapshot,
        fields: tuple[FieldFact, ...],
        calls_by_module: dict[ModuleId, tuple[CallFact, ...]],
        edges_by_module: dict[ModuleId, tuple[UseEdge, ...]],
        models: set[SymbolId],
    ) -> tuple[PydanticFieldFact, ...]:
        result: list[PydanticFieldFact] = []
        for field in fields:
            if field.owner_symbol not in models or not field.is_annotated:
                continue
            calls = calls_by_module.get(field.module_id, ())
            refs = _refs(
                snapshot, field.module_id, field.location, edges_by_module.get(field.module_id)
            )
            annotation = next(
                (
                    ref
                    for ref in refs
                    if ref.written_name == (field.annotation.written if field.annotation else "")
                ),
                None,
            )
            direct = (
                field.value is not None
                and field.value.kind == "Call"
                and (
                    bool(set(field.value.symbols).intersection(_FIELD_SYMBOLS))
                    or any(
                        call.module_id == field.module_id
                        and _contains(field.location, call.location)
                        and call.context.parent_fact_id is None
                        and _matches(call.ref, _FIELD)
                        for call in calls
                    )
                )
            )
            declaration = next(
                (
                    call.ref
                    for call in calls
                    if call.module_id == field.module_id
                    and _contains(field.location, call.location)
                    and direct
                    and call.context.parent_fact_id is None
                    and _matches(call.ref, _FIELD)
                ),
                None,
            )
            call = next(
                (
                    call
                    for call in calls
                    if call.module_id == field.module_id
                    and _contains(field.location, call.location)
                    and declaration is not None
                    and call.ref == declaration
                ),
                None,
            )
            confidence = (
                declaration.state
                if declaration
                else (annotation.state if annotation else ResolutionState.RESOLVED)
            )
            result.append(
                PydanticFieldFact(
                    field.owner_symbol,
                    field.module_id,
                    field,
                    annotation,
                    declaration,
                    _argument(call, "default", 0),
                    _argument(call, "default_factory"),
                    _argument(call, "alias"),
                    _argument(call, "validation_alias"),
                    _argument(call, "serialization_alias"),
                    confidence,
                    field.provenance,
                )
            )
        return tuple(sorted(result, key=lambda x: (x.module_id, x.field.location)))

    def _configs(
        self,
        snapshot: AnalysisSnapshot,
        classes: tuple[ClassFact, ...],
        fields: tuple[FieldFact, ...],
        calls_by_module: dict[ModuleId, tuple[CallFact, ...]],
        edges_by_module: dict[ModuleId, tuple[UseEdge, ...]],
        models: set[SymbolId],
    ) -> tuple[PydanticConfigFact, ...]:
        result: list[PydanticConfigFact] = []
        for field in fields:
            if field.owner_symbol not in models or field.name not in {"Config", "model_config"}:
                continue
            calls = calls_by_module.get(field.module_id, ())
            direct = (
                field.value is not None
                and field.value.kind == "Call"
                and (
                    bool(set(field.value.symbols).intersection(_CONFIG_SYMBOLS))
                    or any(
                        call.module_id == field.module_id
                        and _contains(field.location, call.location)
                        and call.context.parent_fact_id is None
                        and _matches(call.ref, _CONFIG)
                        for call in calls
                    )
                )
            )
            call = next(
                (
                    call
                    for call in calls
                    if call.module_id == field.module_id
                    and _contains(field.location, call.location)
                    and direct
                    and call.context.parent_fact_id is None
                    and _matches(call.ref, _CONFIG)
                ),
                None,
            )
            ref = (
                call.ref
                if call
                else next(
                    iter(
                        _refs(
                            snapshot,
                            field.module_id,
                            field.location,
                            edges_by_module.get(field.module_id),
                        )
                    ),
                    SymbolRef(field.name, ResolutionState.UNRESOLVED, None, (), field.provenance),
                )
            )
            options = tuple(
                (arg.name or str(arg.position), arg.value)
                for arg in (call.arguments if call else ())
            )
            result.append(
                PydanticConfigFact(
                    field.owner_symbol,
                    field.module_id,
                    "v2" if field.name == "model_config" else "v1",
                    field,
                    ref,
                    options,
                    ref.state,
                    field.provenance,
                )
            )
        for config in classes:
            if config.name != "Config" or config.context.lexical_owner not in models:
                continue
            ref = next(
                (
                    edge.ref
                    for edge in snapshot.relations.use_edges
                    if edge.module_id == config.module_id
                    and edge.purpose.value == "base"
                    and _contains(config.location, edge.location)
                ),
                SymbolRef(
                    "Config",
                    ResolutionState.UNRESOLVED,
                    None,
                    (),
                    config.provenance,
                ),
            )
            options = tuple(
                (field.name, field.value)
                for field in fields
                if field.owner_symbol == config.symbol_id and field.value is not None
            )
            result.append(
                PydanticConfigFact(
                    config.context.lexical_owner,
                    config.module_id,
                    "v1",
                    None,
                    ref,
                    options,
                    ref.state,
                    config.provenance,
                )
            )
        return tuple(result)

    def _decorated(
        self,
        snapshot: AnalysisSnapshot,
        models: tuple[PydanticModelFact, ...],
        serializers: bool,
        module_ids: frozenset[ModuleId] | None = None,
    ) -> tuple[PydanticSerializerFact | PydanticValidatorFact, ...]:
        wanted = _SERIALIZERS if serializers else _VALIDATORS
        result: list[PydanticSerializerFact | PydanticValidatorFact] = []
        model_ids = {model.symbol for model in models}
        for module in snapshot.modules.values():
            if module_ids is not None and module.module.id not in module_ids:
                continue
            for dec in module.decorators:
                if dec.context.lexical_owner not in model_ids:
                    continue
                decorator_candidates = (
                    (dec.ref.symbol,) if dec.ref.symbol is not None else dec.ref.candidates
                )
                matched = tuple(
                    candidate for candidate in decorator_candidates if candidate.value in wanted
                )
                if not matched:
                    continue
                names = tuple(
                    str(arg.value.literal_value)
                    for arg in dec.arguments
                    if arg.value.literal_kind == "str"
                )
                cls = PydanticSerializerFact if serializers else PydanticValidatorFact
                result.append(
                    cls(
                        dec.context.lexical_owner,
                        dec.module_id,
                        dec.decorated_symbol,
                        matched[0].value.rsplit(".", 1)[-1],
                        dec.ref,
                        names,
                        dec.ref.state,
                        dec.provenance,
                    )
                )
        return tuple(result)
