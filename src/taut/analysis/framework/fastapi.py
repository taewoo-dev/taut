from __future__ import annotations

from dataclasses import dataclass

from taut.analysis.framework.indexes import grouped
from taut.analysis.providers import CapabilitySpec
from taut.domain.facts import (
    CallFact,
    DecoratorFact,
    FunctionFact,
    ResolutionState,
    SymbolRef,
)
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, SymbolId
from taut.domain.location import ProjectPath, SourceRange
from taut.domain.provenance import Provenance
from taut.domain.relations import Binding, UseEdge
from taut.domain.snapshot import AnalysisSnapshot

FastAPIConfidence = ResolutionState

FASTAPI_PROVIDER_ID = "taut.fastapi"
FASTAPI_PROVIDER_VERSION = "1"
FASTAPI_ENDPOINTS = "taut.fastapi.endpoints@1"
FASTAPI_ROUTERS = "taut.fastapi.routers@1"
FASTAPI_DEPENDENCIES = "taut.fastapi.dependencies@1"
FASTAPI_RESPONSE_MODELS = "taut.fastapi.response_models@1"


@dataclass(frozen=True, order=True)
class FastAPIRouterFact:
    symbol: SymbolId
    module_id: ModuleId
    creation: CallFact
    confidence: FastAPIConfidence
    provenance: Provenance


@dataclass(frozen=True, order=True)
class FastAPIEndpointFact:
    symbol: SymbolId
    module_id: ModuleId
    router: SymbolId
    method: str
    path: str | None
    decorator: DecoratorFact
    function: FunctionFact
    confidence: FastAPIConfidence
    response_model: SymbolId | None
    response_model_ref: SymbolRef | None
    provenance: Provenance


@dataclass(frozen=True, order=True)
class FastAPIDependencyFact:
    function: SymbolId
    module_id: ModuleId
    parameter: str
    provider: SymbolId | None
    provider_ref: SymbolRef | None
    call: CallFact
    confidence: FastAPIConfidence
    provenance: Provenance


@dataclass(frozen=True, order=True)
class FastAPIResponseModelFact:
    endpoint: SymbolId
    module_id: ModuleId
    model: SymbolId | None
    model_ref: SymbolRef
    source: str
    confidence: FastAPIConfidence
    provenance: Provenance


def _confidence(ref: SymbolRef) -> FastAPIConfidence:
    return ref.state


def _provenance(fact: CallFact | DecoratorFact) -> Provenance:
    return fact.provenance


def _path(call: CallFact) -> str | None:
    argument = next((item for item in call.arguments if item.position == 0), None)
    if argument is None or argument.value.literal_kind != "str":
        return None
    return argument.value.literal_value


def _contains(outer: SourceRange, inner: SourceRange) -> bool:
    if outer.path != inner.path:
        return False
    return (outer.start_line, outer.start_column) <= (inner.start_line, inner.start_column) and (
        inner.end_line,
        inner.end_column,
    ) <= (outer.end_line, outer.end_column)


def _confidence_for_receiver(
    snapshot: AnalysisSnapshot,
    receiver_edges: tuple[UseEdge, ...],
    method_state: ResolutionState,
) -> FastAPIConfidence:
    refs = [edge.ref for edge in receiver_edges]
    binding_by_id = {binding.id: binding for binding in snapshot.relations.bindings}
    candidate_bindings = [
        binding_by_id[candidate]
        for edge in receiver_edges
        for candidate in edge.candidate_binding_ids
        if candidate in binding_by_id
    ]
    states = {ref.state for ref in refs}
    if method_state is ResolutionState.AMBIGUOUS or ResolutionState.AMBIGUOUS in states:
        return ResolutionState.AMBIGUOUS
    targets = {binding.target.symbol for binding in candidate_bindings}
    if len(targets) > 1:
        return ResolutionState.AMBIGUOUS
    if any(binding.context.guard.value == "conditional" for binding in candidate_bindings):
        return ResolutionState.CONDITIONAL
    if ResolutionState.CONDITIONAL in states:
        return ResolutionState.CONDITIONAL
    return refs[0].state if refs else ResolutionState.RESOLVED


class FastAPIProvider:
    """Extract FastAPI structure from the resolver-owned semantic snapshot.

    This provider intentionally does not inspect source text or syntax trees.  Framework
    recognition is based on canonical ``SymbolRef`` values emitted by the language adapter.
    """

    id = FASTAPI_PROVIDER_ID
    version = FASTAPI_PROVIDER_VERSION
    provides = frozenset(
        CapabilitySpec(item)
        for item in (
            FASTAPI_ENDPOINTS,
            FASTAPI_ROUTERS,
            FASTAPI_DEPENDENCIES,
            FASTAPI_RESPONSE_MODELS,
        )
    )

    def analyze(self, snapshot: AnalysisSnapshot) -> FrozenMap[str, tuple[object, ...]]:
        functions = {
            function.symbol_id: function
            for module in snapshot.modules.values()
            for function in module.functions
        }
        bindings_by_module = dict(grouped(snapshot.relations.bindings, lambda item: item.module_id))
        edges_by_path_line = dict(
            grouped(
                snapshot.relations.use_edges,
                lambda item: (item.location.path, item.location.start_line),
            )
        )
        routers = self._routers(snapshot, bindings_by_module)
        endpoints = self._endpoints(snapshot, functions, routers, edges_by_path_line)
        dependencies = self._dependencies(snapshot, functions, edges_by_path_line)
        models = self._response_models(endpoints)
        return FrozenMap(
            (
                (FASTAPI_ROUTERS, routers),
                (FASTAPI_ENDPOINTS, endpoints),
                (FASTAPI_DEPENDENCIES, dependencies),
                (FASTAPI_RESPONSE_MODELS, models),
            )
        )

    def analyze_incremental(
        self,
        snapshot: AnalysisSnapshot,
        previous: FrozenMap[str, tuple[object, ...]],
        impacted: frozenset[ModuleId],
    ) -> FrozenMap[str, tuple[object, ...]]:
        functions = {
            f.symbol_id: f for module in snapshot.modules.values() for f in module.functions
        }
        bindings = dict(grouped(snapshot.relations.bindings, lambda item: item.module_id))
        edges = dict(
            grouped(
                snapshot.relations.use_edges,
                lambda item: (item.location.path, item.location.start_line),
            )
        )
        routers = self._routers(snapshot, bindings)
        endpoints = self._endpoints(snapshot, functions, routers, edges)
        fresh: dict[str, tuple[object, ...]] = {
            FASTAPI_ROUTERS: routers,
            FASTAPI_ENDPOINTS: endpoints,
            FASTAPI_DEPENDENCIES: self._dependencies(snapshot, functions, edges),
            FASTAPI_RESPONSE_MODELS: self._response_models(endpoints),
        }
        merged: list[tuple[str, tuple[object, ...]]] = []
        for capability, values in fresh.items():
            old = previous.get(capability, ())
            kept = tuple(item for item in old if getattr(item, "module_id", None) not in impacted)
            recalculated = tuple(
                item for item in values if getattr(item, "module_id", None) in impacted
            )
            merged.append((capability, tuple(sorted((*kept, *recalculated), key=repr))))
        return FrozenMap(tuple(sorted(merged)))

    def _routers(
        self, snapshot: AnalysisSnapshot, bindings_by_module: dict[ModuleId, tuple[Binding, ...]]
    ) -> tuple[FastAPIRouterFact, ...]:
        result: list[FastAPIRouterFact] = []
        for module in snapshot.modules.values():
            for call in module.calls:
                if call.ref.symbol not in {
                    SymbolId("fastapi.APIRouter"),
                    SymbolId("fastapi.routing.APIRouter"),
                    SymbolId("fastapi.FastAPI"),
                    SymbolId("fastapi.applications.FastAPI"),
                }:
                    continue
                candidates = [
                    binding
                    for binding in bindings_by_module.get(call.module_id, ())
                    if binding.module_id == call.module_id
                    and binding.location.start_line == call.location.start_line
                    and binding.location.start_column <= call.location.start_column
                    and binding.target.symbol is not None
                ]
                owner = (
                    max(candidates, key=lambda item: item.location.start_column).target.symbol
                    if candidates
                    else None
                )
                if owner is None:
                    continue
                result.append(
                    FastAPIRouterFact(
                        owner, call.module_id, call, _confidence(call.ref), _provenance(call)
                    )
                )
        return tuple(
            sorted(result, key=lambda item: (item.module_id, item.creation.location, item.symbol))
        )

    def _endpoints(
        self,
        snapshot: AnalysisSnapshot,
        functions: dict[SymbolId, FunctionFact],
        routers: tuple[FastAPIRouterFact, ...],
        edges_by_path_line: dict[tuple[ProjectPath, int], tuple[UseEdge, ...]],
    ) -> tuple[FastAPIEndpointFact, ...]:
        router_symbols = {item.symbol for item in routers}
        result: list[FastAPIEndpointFact] = []
        for module in snapshot.modules.values():
            for decorator in module.decorators:
                method_ref = decorator.ref
                if method_ref.state is ResolutionState.DYNAMIC:
                    continue
                written_parts = method_ref.written_name.rsplit(".", 1)
                method = written_parts[-1]
                receiver_name = written_parts[0] if len(written_parts) == 2 else ""
                receiver_symbol = (
                    method_ref.symbol.value.rsplit(".", 1)[0]
                    if method_ref.symbol is not None
                    else ""
                )
                if method not in {"get", "post", "put", "patch", "delete", "options", "head"}:
                    continue
                receiver_edges = tuple(
                    edge
                    for edge in edges_by_path_line.get(
                        (decorator.location.path, decorator.location.start_line), ()
                    )
                    if edge.ref.written_name == receiver_name
                )
                if method_ref.symbol is not None and not (
                    receiver_symbol
                    in {
                        "fastapi.APIRouter",
                        "fastapi.routing.APIRouter",
                        "fastapi.FastAPI",
                        "fastapi.applications.FastAPI",
                    }
                    or (receiver_symbol and SymbolId(receiver_symbol) in router_symbols)
                    or any(
                        candidate in router_symbols
                        for edge in receiver_edges
                        for candidate in edge.ref.candidates
                    )
                ):
                    continue
                if method_ref.symbol is None and not receiver_edges:
                    continue
                function = functions.get(decorator.decorated_symbol)
                if function is None:
                    continue
                router = next(
                    (
                        edge.ref.symbol
                        for edge in edges_by_path_line.get(
                            (decorator.location.path, decorator.location.start_line), ()
                        )
                        if edge.location == decorator.location and edge.ref.symbol in router_symbols
                    ),
                    None,
                )
                if router is None:
                    # The resolver may retain a conditional/ambiguous receiver; preserve its
                    # confidence while exposing the canonical candidate when one exists.
                    receiver = receiver_edges[0].ref if receiver_edges else method_ref
                    router = receiver.symbol or (
                        receiver.candidates[0] if receiver.candidates else method_ref.symbol
                    )
                if router is None:
                    continue
                if router.value.rsplit(".", 1)[-1] in {
                    "get",
                    "post",
                    "put",
                    "patch",
                    "delete",
                    "options",
                    "head",
                }:
                    router = SymbolId(router.value.rsplit(".", 1)[0])
                response_ref = next(
                    (
                        edge.ref
                        for edge in edges_by_path_line.get(
                            (decorator.location.path, decorator.location.start_line), ()
                        )
                        if edge.context.argument_name == "response_model"
                    ),
                    None,
                )
                response_symbol = response_ref.symbol if response_ref is not None else None
                result.append(
                    FastAPIEndpointFact(
                        function.symbol_id,
                        module.module.id,
                        router,
                        method,
                        _path(decorator_as_call(decorator)),
                        decorator,
                        function,
                        _confidence_for_receiver(snapshot, receiver_edges, method_ref.state),
                        response_symbol,
                        response_ref,
                        _provenance(decorator),
                    )
                )
        return tuple(
            sorted(result, key=lambda item: (item.module_id, item.decorator.location, item.symbol))
        )

    def _dependencies(
        self,
        snapshot: AnalysisSnapshot,
        functions: dict[SymbolId, FunctionFact],
        edges_by_path_line: dict[tuple[ProjectPath, int], tuple[UseEdge, ...]],
    ) -> tuple[FastAPIDependencyFact, ...]:
        result: list[FastAPIDependencyFact] = []
        for module in snapshot.modules.values():
            for call in module.calls:
                if call.ref.symbol not in {
                    SymbolId("fastapi.Depends"),
                    SymbolId("fastapi.params.Depends"),
                }:
                    continue
                match = next(
                    (
                        (function, item)
                        for function in functions.values()
                        if function.module_id == call.module_id
                        for item in function.parameters
                        if item.default_expression is not None
                        and item.default_location is not None
                        and _contains(item.default_location, call.location)
                        and call.ref.symbol in item.default_expression.symbols
                        and item.default_expression.arguments == call.arguments
                    ),
                    None,
                )
                if match is None:
                    continue
                function, parameter_fact = match
                owner = function.symbol_id
                parameter = parameter_fact.name
                provider_ref = next(
                    (
                        edge.ref
                        for edge in edges_by_path_line.get(
                            (call.location.path, call.location.start_line), ()
                        )
                        if _contains(call.location, edge.location)
                        and edge.context.position.value == "argument"
                        and edge.context.argument_position == 0
                    ),
                    None,
                )
                provider = provider_ref.symbol if provider_ref is not None else None
                result.append(
                    FastAPIDependencyFact(
                        owner,
                        module.module.id,
                        parameter,
                        provider,
                        provider_ref,
                        call,
                        _confidence(provider_ref) if provider_ref is not None else call.ref.state,
                        _provenance(call),
                    )
                )
        return tuple(
            sorted(result, key=lambda item: (item.module_id, item.call.location, item.function))
        )

    def _response_models(
        self, endpoints: tuple[FastAPIEndpointFact, ...]
    ) -> tuple[FastAPIResponseModelFact, ...]:
        return tuple(
            FastAPIResponseModelFact(
                item.symbol,
                item.module_id,
                item.response_model,
                item.response_model_ref,
                "response_model",
                item.response_model_ref.state,
                item.provenance,
            )
            for item in endpoints
            if item.response_model_ref is not None
        )


def decorator_as_call(decorator: DecoratorFact) -> CallFact:
    return CallFact(
        decorator.id,
        decorator.module_id,
        decorator.ref,
        None,
        len(decorator.arguments),
        tuple(sorted(item.name for item in decorator.arguments if item.name is not None)),
        False,
        decorator.arguments,
        (),
        decorator.location,
        decorator.provenance,
        decorator.context,
    )
