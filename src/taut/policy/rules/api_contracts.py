from __future__ import annotations

from taut.analysis.framework.fastapi import (
    FASTAPI_ENDPOINTS,
    FASTAPI_RESPONSE_MODELS,
    FASTAPI_ROUTERS,
)
from taut.analysis.framework.pydantic import PYDANTIC_FIELDS
from taut.domain.evaluations import (
    ChangeImpact,
    EvaluationReason,
    RuleTarget,
    RuleTargetRef,
    RuleVerdict,
)
from taut.domain.facts import (
    AnalysisStage,
    CallFact,
    DecoratorFact,
    ExpressionSummary,
)
from taut.domain.findings import Finding
from taut.domain.ids import RuleId, SymbolId
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.api_field_metadata import field_metadata_names, is_base_model
from taut.policy.rules.helpers import (
    build_policy_finding,
    target_uncertainty,
)

ENDPOINT_RULE_ID = RuleId("API001")
FIELD_RULE_ID = RuleId("API002")
ROUTER_METADATA_RULE_ID = RuleId("API003")
RULE_VERSION = 1
FIELD_RULE_VERSION = 2
ROUTER_METADATA_RULE_VERSION = 2
_HTTP_METHODS = {"delete", "get", "head", "options", "patch", "post", "put", "trace"}
_NO_BODY_RETURNS = ("FileResponse", "NoReturn", "Never", "Response", "StreamingResponse")
_ROUTER_CONSTRUCTORS = frozenset({"fastapi.APIRouter", "fastapi.routing.APIRouter"})
_ROUTER_REGISTRATIONS = frozenset(
    {
        "fastapi.APIRouter.include_router",
        "fastapi.FastAPI.include_router",
        "fastapi.applications.FastAPI.include_router",
        "fastapi.routing.APIRouter.include_router",
    }
)
_ROUTER_REGISTRATION_SYMBOLS = tuple(SymbolId(symbol) for symbol in sorted(_ROUTER_REGISTRATIONS))


def _is_endpoint(decorator: DecoratorFact) -> bool:
    symbol = decorator.ref.symbol
    if symbol is None:
        return False
    method = symbol.value.rsplit(".", maxsplit=1)[-1]
    return method in _HTTP_METHODS and "Router" in symbol.value


def _keyword(decorator: DecoratorFact, name: str) -> ExpressionSummary | None:
    return next((argument.value for argument in decorator.arguments if argument.name == name), None)


def _mapping_keys(expression: ExpressionSummary, context: PolicyContext) -> tuple[str, ...] | None:
    if expression.mapping_keys is not None:
        return expression.mapping_keys
    functions = {
        context.model.canonical_symbol(function.symbol_id): function
        for module_id in context.model.modules()
        for function in context.model.module(module_id).functions
    }
    fields = {
        context.model.canonical_symbol(field.symbol_id): field
        for module_id in context.model.modules()
        for field in context.model.module(module_id).fields
        if field.value is not None
    }

    def keys_for_symbol(
        symbol: SymbolId, visiting: frozenset[SymbolId] = frozenset()
    ) -> tuple[str, ...] | None:
        canonical = context.model.canonical_symbol(symbol)
        if canonical in visiting:
            return None
        function = functions.get(canonical)
        if function is not None and function.returned_mapping_keys is not None:
            return function.returned_mapping_keys
        if function is not None:
            forwarded = tuple(
                keys
                for returned in function.returned_symbols
                if (keys := keys_for_symbol(returned, visiting | {canonical})) is not None
            )
            if forwarded:
                return _intersect_keys(forwarded)
        field = fields.get(canonical)
        if field is not None and field.value is not None and field.value.mapping_keys is not None:
            return field.value.mapping_keys
        return None

    candidates = tuple(
        keys for symbol in expression.symbols if (keys := keys_for_symbol(symbol)) is not None
    )
    if not candidates:
        return None
    return _intersect_keys(candidates)


def _intersect_keys(candidates: tuple[tuple[str, ...], ...]) -> tuple[str, ...]:
    common = set(candidates[0])
    for candidate in candidates[1:]:
        common.intersection_update(candidate)
    return tuple(sorted(common))


def _keyword_state(decorator: DecoratorFact, name: str, context: PolicyContext) -> bool | None:
    if _keyword(decorator, name) is not None:
        return True
    unpacked = tuple(
        argument.value for argument in decorator.arguments[1:] if argument.name is None
    )
    if not unpacked:
        return False
    unknown = False
    for expression in unpacked:
        keys = _mapping_keys(expression, context)
        if keys is None:
            unknown = True
        elif name in keys:
            return True
    return None if unknown else False


def _is_no_body_type(expression: ExpressionSummary | None) -> bool:
    if expression is None:
        return False
    names = {symbol.value.rsplit(".", maxsplit=1)[-1] for symbol in expression.symbols}
    return bool(names.intersection(_NO_BODY_RETURNS)) or expression.written.strip("'\"") in (
        _NO_BODY_RETURNS
    )


def _no_response_model_needed(
    decorator: DecoratorFact, return_annotation: ExpressionSummary | None
) -> bool:
    status = _keyword(decorator, "status_code")
    if status is not None and (
        status.literal_value == "204" or "HTTP_204_NO_CONTENT" in status.written
    ):
        return True
    response_class = _keyword(decorator, "response_class")
    if _is_no_body_type(response_class):
        return True
    return _is_no_body_type(return_annotation)


class EndpointDocumentationRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("API001 requires a module target")
        role = context.classification.get(target.module_id).role
        if role not in context.policy.code.router_roles:
            return RuleEvaluation(ENDPOINT_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        uncertainty = target_uncertainty(
            ENDPOINT_RULE_ID, target, context, (FASTAPI_ENDPOINTS, FASTAPI_RESPONSE_MODELS), True
        )
        if uncertainty is not None:
            return uncertainty
        module = context.model.module(target.module_id)
        functions = {function.symbol_id: function for function in module.functions}
        findings: list[Finding] = []
        coverage_gaps: list[EvaluationReason] = []
        for decorator in module.decorators:
            if not _is_endpoint(decorator):
                continue
            function = functions.get(decorator.decorated_symbol)
            if function is None:
                continue
            if not function.has_docstring:
                findings.append(
                    build_policy_finding(
                        ENDPOINT_RULE_ID,
                        target.module_id,
                        function.symbol_id,
                        function.id,
                        function.location,
                        "api.endpoint_docstring_missing",
                        "docstring",
                    )
                )
            responses = _keyword_state(decorator, "responses", context)
            if responses is False:
                findings.append(
                    build_policy_finding(
                        ENDPOINT_RULE_ID,
                        target.module_id,
                        function.symbol_id,
                        decorator.id,
                        decorator.location,
                        "api.responses_missing",
                        "responses",
                    )
                )
            elif responses is None:
                coverage_gaps.append(
                    EvaluationReason(
                        "unresolved_mapping",
                        f"{function.symbol_id.value}의 responses mapping을 확정하지 못했습니다.",
                    )
                )
            response_model = _keyword_state(decorator, "response_model", context)
            if response_model is False and not _no_response_model_needed(
                decorator, function.return_annotation
            ):
                findings.append(
                    build_policy_finding(
                        ENDPOINT_RULE_ID,
                        target.module_id,
                        function.symbol_id,
                        decorator.id,
                        decorator.location,
                        "api.response_model_missing",
                        "response_model",
                    )
                )
            elif response_model is None:
                coverage_gaps.append(
                    EvaluationReason(
                        "unresolved_mapping",
                        f"{function.symbol_id.value}의 response_model mapping을 "
                        "확정하지 못했습니다.",
                    )
                )
        if findings:
            return RuleEvaluation(
                ENDPOINT_RULE_ID,
                target,
                RuleVerdict.FAIL,
                tuple(findings),
                coverage_gaps=tuple(sorted(set(coverage_gaps), key=lambda item: item.message)),
            )
        if coverage_gaps:
            return RuleEvaluation(
                ENDPOINT_RULE_ID,
                target,
                RuleVerdict.INDETERMINATE,
                (),
                coverage_gaps[0],
                tuple(sorted(set(coverage_gaps), key=lambda item: item.message)),
            )
        return RuleEvaluation(ENDPOINT_RULE_ID, target, RuleVerdict.PASS, ())


class PublicFieldDocumentationRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("API002 requires a module target")
        role = context.classification.get(target.module_id).role
        if role not in context.policy.code.schema_roles:
            return RuleEvaluation(FIELD_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        uncertainty = target_uncertainty(FIELD_RULE_ID, target, context, (PYDANTIC_FIELDS,), True)
        if uncertainty is not None:
            return uncertainty
        module = context.model.module(target.module_id)
        classes = {
            class_fact.symbol_id: class_fact
            for class_fact in module.classes
            if is_base_model(class_fact)
        }
        findings: list[Finding] = []
        for field in module.fields:
            if (
                field.owner_symbol not in classes
                or field.name.startswith("_")
                or field.name == "model_config"
            ):
                continue
            names = field_metadata_names(field, module.calls)
            missing: list[str] = []
            if names is None:
                missing.extend(("description", "examples"))
            else:
                if "description" not in names:
                    missing.append("description")
                if (
                    "examples" not in names
                    and field.owner_symbol not in context.policy.code.generic_schema_bases
                ):
                    missing.append("examples")
            if missing:
                findings.append(
                    build_policy_finding(
                        FIELD_RULE_ID,
                        target.module_id,
                        field.owner_symbol,
                        field.id,
                        field.location,
                        "api.field_metadata_missing",
                        ",".join(missing),
                        rule_version=FIELD_RULE_VERSION,
                    )
                )
        if findings:
            return RuleEvaluation(FIELD_RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(FIELD_RULE_ID, target, RuleVerdict.PASS, ())


def _call_symbol(call: CallFact) -> str | None:
    if call.ref.symbol is None:
        return None
    return call.ref.symbol.value


def _argument(call: CallFact, name: str) -> ExpressionSummary | None:
    return next((item.value for item in call.arguments if item.name == name), None)


def _positional_argument(call: CallFact, position: int) -> ExpressionSummary | None:
    return next(
        (item.value for item in call.arguments if item.name is None and item.position == position),
        None,
    )


def _has_non_empty_tags(call: CallFact) -> bool:
    tags = _argument(call, "tags")
    return tags is not None and tags.collection_size != 0


def _router_symbols_for_constructor(call: CallFact, context: PolicyContext) -> frozenset[SymbolId]:
    module = context.model.module(call.module_id)
    return frozenset(
        field.symbol_id
        for field in module.fields
        if field.owner_symbol is None
        and field.value is not None
        and field.location.start_line == call.location.start_line
        and any(symbol.value in _ROUTER_CONSTRUCTORS for symbol in field.value.symbols)
    )


def _router_registration_tags(
    target: RuleTargetRef,
    context: PolicyContext,
) -> dict[SymbolId, tuple[bool, ...]]:
    if target.module_id is None:
        return {}
    target_zone = context.classification.get(target.module_id).zone
    registrations: dict[SymbolId, list[bool]] = {}
    for registration_symbol in _ROUTER_REGISTRATION_SYMBOLS:
        for call in context.indexes.calls_by_symbol.get(registration_symbol, ()):
            if context.classification.get(call.module_id).zone != target_zone:
                continue
            router = _argument(call, "router") or _positional_argument(call, 0)
            if router is None:
                continue
            for symbol in router.symbols:
                registrations.setdefault(symbol, []).append(_has_non_empty_tags(call))
    return {symbol: tuple(values) for symbol, values in registrations.items()}


def _all_registrations_have_tags(
    router_symbols: frozenset[SymbolId],
    registrations: dict[SymbolId, tuple[bool, ...]],
) -> bool:
    states = tuple(state for symbol in router_symbols for state in registrations.get(symbol, ()))
    return bool(states) and all(states)


class RouterMetadataRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("API003 requires a module target")
        role = context.classification.get(target.module_id).role
        if role not in context.policy.code.router_roles:
            return RuleEvaluation(
                ROUTER_METADATA_RULE_ID,
                target,
                RuleVerdict.NOT_APPLICABLE,
                (),
            )
        uncertainty = target_uncertainty(
            ROUTER_METADATA_RULE_ID, target, context, (FASTAPI_ROUTERS,), True
        )
        if uncertainty is not None:
            return uncertainty
        findings: list[Finding] = []
        registrations = _router_registration_tags(target, context)
        for call in context.model.module(target.module_id).calls:
            symbol = _call_symbol(call)
            if symbol in _ROUTER_CONSTRUCTORS:
                router_symbols = _router_symbols_for_constructor(call, context)
                if not _has_non_empty_tags(call) and not _all_registrations_have_tags(
                    router_symbols,
                    registrations,
                ):
                    findings.append(
                        build_policy_finding(
                            ROUTER_METADATA_RULE_ID,
                            target.module_id,
                            call.enclosing_symbol or SymbolId(f"{target.module_id.value}.router"),
                            call.id,
                            call.location,
                            "api.router_tags_missing",
                            "tags",
                            rule_version=ROUTER_METADATA_RULE_VERSION,
                        )
                    )
            if symbol in {"fastapi.Query", "fastapi.params.Query"} and "description" not in {
                argument.name for argument in call.arguments
            }:
                findings.append(
                    build_policy_finding(
                        ROUTER_METADATA_RULE_ID,
                        target.module_id,
                        call.enclosing_symbol or SymbolId(f"{target.module_id.value}.query"),
                        call.id,
                        call.location,
                        "api.query_description_missing",
                        "description",
                        rule_version=ROUTER_METADATA_RULE_VERSION,
                    )
                )
        if findings:
            return RuleEvaluation(
                ROUTER_METADATA_RULE_ID,
                target,
                RuleVerdict.FAIL,
                tuple(findings),
            )
        return RuleEvaluation(ROUTER_METADATA_RULE_ID, target, RuleVerdict.PASS, ())


def api_rule_definitions() -> tuple[RuleDefinition, ...]:
    requirements = RuleRequirements(frozenset(), AnalysisStage.FACTS_READY, False, False)
    project_requirements = RuleRequirements(
        frozenset(),
        AnalysisStage.FACTS_READY,
        False,
        True,
    )
    return (
        RuleDefinition(
            ENDPOINT_RULE_ID,
            RULE_VERSION,
            "HTTP Endpoint 문서",
            "Endpoint에 docstring, responses와 정상 응답 response_model을 명시하세요.",
            RuleTarget.MODULE,
            requirements,
            ChangeImpact.SELF,
            EndpointDocumentationRule(),
            ("tests/fixtures/rules/api_endpoint/compliant.py",),
            ("tests/fixtures/rules/api_endpoint/violation.py",),
        ),
        RuleDefinition(
            FIELD_RULE_ID,
            FIELD_RULE_VERSION,
            "공개 API 필드 문서",
            "공개 Schema 필드에 설명과 실제 예시를 명시하세요.",
            RuleTarget.MODULE,
            requirements,
            ChangeImpact.SELF,
            PublicFieldDocumentationRule(),
            ("tests/fixtures/rules/api_field/compliant.py",),
            ("tests/fixtures/rules/api_field/violation.py",),
        ),
        RuleDefinition(
            ROUTER_METADATA_RULE_ID,
            ROUTER_METADATA_RULE_VERSION,
            "Router 태그와 Query 설명",
            "APIRouter 또는 include_router에는 tags를, Query 매개변수에는 description을 "
            "명시하세요.",
            RuleTarget.MODULE,
            project_requirements,
            ChangeImpact.PROJECT,
            RouterMetadataRule(),
            ("tests/fixtures/rules/api_metadata/compliant.py",),
            ("tests/fixtures/rules/api_metadata/violation.py",),
        ),
    )
