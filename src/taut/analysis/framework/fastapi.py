from __future__ import annotations

from dataclasses import dataclass

from taut.analysis.providers import CapabilitySpec
from taut.domain.facts import (
    CallFact,
    DecoratorFact,
    ExpressionSummary,
    FunctionFact,
    ResolutionState,
    SymbolRef,
)
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, SymbolId
from taut.domain.provenance import Provenance
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
    provenance: Provenance


@dataclass(frozen=True, order=True)
class FastAPIDependencyFact:
    function: SymbolId
    module_id: ModuleId
    parameter: str
    provider: SymbolId | None
    call: CallFact
    confidence: FastAPIConfidence
    provenance: Provenance


@dataclass(frozen=True, order=True)
class FastAPIResponseModelFact:
    endpoint: SymbolId
    module_id: ModuleId
    model: SymbolId
    source: str
    confidence: FastAPIConfidence
    provenance: Provenance


def _confidence(ref: SymbolRef) -> FastAPIConfidence:
    return ref.state


def _provenance(fact: CallFact | DecoratorFact) -> Provenance:
    return fact.provenance


def _argument(call: CallFact, name: str) -> ExpressionSummary | None:
    return next((argument.value for argument in call.arguments if argument.name == name), None)


def _path(call: CallFact) -> str | None:
    argument = next((item for item in call.arguments if item.position == 0), None)
    if argument is None or argument.value.literal_kind != "str":
        return None
    return argument.value.literal_value


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
        routers = self._routers(snapshot)
        endpoints = self._endpoints(snapshot, functions, routers)
        dependencies = self._dependencies(snapshot, functions)
        models = self._response_models(endpoints)
        return FrozenMap(
            (
                (FASTAPI_ROUTERS, routers),
                (FASTAPI_ENDPOINTS, endpoints),
                (FASTAPI_DEPENDENCIES, dependencies),
                (FASTAPI_RESPONSE_MODELS, models),
            )
        )

    def _routers(self, snapshot: AnalysisSnapshot) -> tuple[FastAPIRouterFact, ...]:
        result: list[FastAPIRouterFact] = []
        for module in snapshot.modules.values():
            for call in module.calls:
                if call.ref.symbol not in {
                    SymbolId("fastapi.APIRouter"),
                    SymbolId("fastapi.routing.APIRouter"),
                }:
                    continue
                candidates = [
                    binding
                    for binding in snapshot.relations.bindings
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
    ) -> tuple[FastAPIEndpointFact, ...]:
        router_symbols = {item.symbol for item in routers}
        result: list[FastAPIEndpointFact] = []
        for module in snapshot.modules.values():
            for decorator in module.decorators:
                method_ref = decorator.ref
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
                    for edge in snapshot.relations.use_edges
                    if edge.location.path == decorator.location.path
                    and edge.location.start_line == decorator.location.start_line
                    and edge.ref.written_name == receiver_name
                )
                if method_ref.symbol is not None and not (
                    receiver_symbol in {"fastapi.APIRouter", "fastapi.routing.APIRouter"}
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
                        for edge in snapshot.relations.use_edges
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
                receiver_ref = next(
                    (
                        edge.ref
                        for edge in snapshot.relations.use_edges
                        if edge.location.path == decorator.location.path
                        and edge.location.start_line == decorator.location.start_line
                        and edge.ref.written_name == receiver_name
                    ),
                    method_ref,
                )
                response = _argument(decorator_as_call(decorator), "response_model")
                response_symbol = (
                    response.symbols[0]
                    if response is not None and len(response.symbols) == 1
                    else None
                )
                result.append(
                    FastAPIEndpointFact(
                        function.symbol_id,
                        module.module.id,
                        router,
                        method,
                        _path(decorator_as_call(decorator)),
                        decorator,
                        function,
                        _confidence(receiver_ref),
                        response_symbol,
                        _provenance(decorator),
                    )
                )
        return tuple(
            sorted(result, key=lambda item: (item.module_id, item.decorator.location, item.symbol))
        )

    def _dependencies(
        self, snapshot: AnalysisSnapshot, functions: dict[SymbolId, FunctionFact]
    ) -> tuple[FastAPIDependencyFact, ...]:
        result: list[FastAPIDependencyFact] = []
        for module in snapshot.modules.values():
            for call in module.calls:
                if call.ref.symbol not in {
                    SymbolId("fastapi.Depends"),
                    SymbolId("fastapi.params.Depends"),
                }:
                    continue
                owner = next(
                    (
                        function.symbol_id
                        for function in functions.values()
                        if function.module_id == call.module_id
                        and function.location.start_line == call.location.start_line
                    ),
                    None,
                )
                if owner is None:
                    continue
                parameter = next(
                    (item.name for item in functions[owner].parameters if item.has_default), ""
                )
                provider = next(
                    (
                        argument.value.symbols[0]
                        for argument in call.arguments
                        if argument.value.symbols and argument.position == 0
                    ),
                    None,
                )
                provider_ref = next(
                    (
                        edge.ref
                        for edge in snapshot.relations.use_edges
                        if edge.location == call.location
                        and edge.context.position.value == "argument"
                    ),
                    call.ref,
                )
                result.append(
                    FastAPIDependencyFact(
                        owner,
                        module.module.id,
                        parameter,
                        provider,
                        call,
                        _confidence(provider_ref),
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
                "response_model",
                item.confidence,
                item.provenance,
            )
            for item in endpoints
            if item.response_model is not None
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
