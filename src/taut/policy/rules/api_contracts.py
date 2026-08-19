from __future__ import annotations

from taut.domain.evaluations import ChangeImpact, RuleTarget, RuleTargetRef, RuleVerdict
from taut.domain.facts import (
    AnalysisStage,
    CallFact,
    ClassFact,
    DecoratorFact,
    ExpressionSummary,
    FieldFact,
)
from taut.domain.findings import EvidenceItem, Finding
from taut.domain.ids import FactId, ModuleId, RuleId, SymbolId
from taut.domain.location import SourceRange
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import build_finding

ENDPOINT_RULE_ID = RuleId("API001")
FIELD_RULE_ID = RuleId("API002")
ROUTER_METADATA_RULE_ID = RuleId("API003")
MAPPING_RULE_ID = RuleId("SCHEMA003")
RULE_VERSION = 1
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


def _finding(
    rule_id: RuleId,
    module_id: ModuleId,
    enclosing_symbol: SymbolId,
    subject: FactId,
    location: SourceRange,
    message_key: str,
    missing: str,
    rule_version: int = RULE_VERSION,
) -> Finding:
    return build_finding(
        rule_id=rule_id,
        rule_version=rule_version,
        module_id=module_id,
        enclosing_symbol=enclosing_symbol,
        subject=subject,
        normalized_subject=f"{missing}:{subject.value}",
        message_key=message_key,
        arguments=(("symbol", enclosing_symbol.value), ("missing", missing)),
        location=location,
        evidence=(
            EvidenceItem("symbol", enclosing_symbol.value),
            EvidenceItem("missing", missing),
        ),
    )


def _is_endpoint(decorator: DecoratorFact) -> bool:
    symbol = decorator.ref.symbol
    if symbol is None:
        return False
    method = symbol.value.rsplit(".", maxsplit=1)[-1]
    return method in _HTTP_METHODS and "Router" in symbol.value


def _keyword(decorator: DecoratorFact, name: str) -> ExpressionSummary | None:
    return next((argument.value for argument in decorator.arguments if argument.name == name), None)


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
        module = context.model.module(target.module_id)
        functions = {function.symbol_id: function for function in module.functions}
        findings: list[Finding] = []
        for decorator in module.decorators:
            if not _is_endpoint(decorator):
                continue
            function = functions.get(decorator.decorated_symbol)
            if function is None:
                continue
            if not function.has_docstring:
                findings.append(
                    _finding(
                        ENDPOINT_RULE_ID,
                        target.module_id,
                        function.symbol_id,
                        function.id,
                        function.location,
                        "api.endpoint_docstring_missing",
                        "docstring",
                    )
                )
            if _keyword(decorator, "responses") is None:
                findings.append(
                    _finding(
                        ENDPOINT_RULE_ID,
                        target.module_id,
                        function.symbol_id,
                        decorator.id,
                        decorator.location,
                        "api.responses_missing",
                        "responses",
                    )
                )
            if _keyword(decorator, "response_model") is None and not _no_response_model_needed(
                decorator, function.return_annotation
            ):
                findings.append(
                    _finding(
                        ENDPOINT_RULE_ID,
                        target.module_id,
                        function.symbol_id,
                        decorator.id,
                        decorator.location,
                        "api.response_model_missing",
                        "response_model",
                    )
                )
        if findings:
            return RuleEvaluation(ENDPOINT_RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(ENDPOINT_RULE_ID, target, RuleVerdict.PASS, ())


def _base_model(class_fact: ClassFact) -> bool:
    return any(
        symbol.value in {"pydantic.BaseModel", "pydantic.main.BaseModel"}
        for base in class_fact.bases
        for symbol in base.symbols
    )


def _field_call(field: FieldFact) -> bool:
    return bool(
        field.value
        and any(
            symbol.value in {"pydantic.Field", "pydantic.fields.Field"}
            for symbol in field.value.symbols
        )
    )


class PublicFieldDocumentationRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("API002 requires a module target")
        role = context.classification.get(target.module_id).role
        if role not in context.policy.code.schema_roles:
            return RuleEvaluation(FIELD_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        module = context.model.module(target.module_id)
        classes = {
            class_fact.symbol_id: class_fact
            for class_fact in module.classes
            if _base_model(class_fact)
        }
        findings: list[Finding] = []
        for field in module.fields:
            if (
                field.owner_symbol not in classes
                or field.name.startswith("_")
                or field.name == "model_config"
            ):
                continue
            missing: list[str] = []
            if not _field_call(field) or field.value is None:
                missing.extend(("description", "examples"))
            else:
                names = {argument.name for argument in field.value.arguments}
                if "description" not in names:
                    missing.append("description")
                if (
                    "examples" not in names
                    and field.owner_symbol not in context.policy.code.generic_schema_bases
                ):
                    missing.append("examples")
            if missing:
                findings.append(
                    _finding(
                        FIELD_RULE_ID,
                        target.module_id,
                        field.owner_symbol,
                        field.id,
                        field.location,
                        "api.field_metadata_missing",
                        ",".join(missing),
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
                        _finding(
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
                    _finding(
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


class ResponseMappingRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("SCHEMA003 requires a module target")
        role = context.classification.get(target.module_id).role
        module = context.model.module(target.module_id)
        findings: list[Finding] = []
        if role in context.policy.code.schema_roles:
            functions = {function.symbol_id: function for function in module.functions}
            for class_fact in module.classes:
                if not class_fact.name.endswith(("Response", "ResponseModel")):
                    continue
                method_symbol = SymbolId(f"{class_fact.symbol_id.value}.from_internal")
                method = functions.get(method_symbol)
                if method is None:
                    findings.append(
                        _finding(
                            MAPPING_RULE_ID,
                            target.module_id,
                            class_fact.symbol_id,
                            class_fact.id,
                            class_fact.location,
                            "schema.from_internal_missing",
                            "from_internal",
                        )
                    )
                    continue
                unsafe = tuple(
                    call
                    for call in module.calls
                    if call.enclosing_symbol == method_symbol
                    and (
                        call.has_keyword_unpack
                        or call.ref.written_name.rsplit(".", maxsplit=1)[-1]
                        in {"asdict", "model_dump", "model_validate", "vars"}
                    )
                )
                findings.extend(
                    _finding(
                        MAPPING_RULE_ID,
                        target.module_id,
                        class_fact.symbol_id,
                        call.id,
                        call.location,
                        "schema.bulk_mapping",
                        call.ref.written_name,
                    )
                    for call in unsafe
                )
        elif role in context.policy.code.router_roles:
            for call in module.calls:
                symbol = call.ref.symbol
                if symbol is None:
                    continue
                class_name = symbol.value.rsplit(".", maxsplit=1)[-1]
                if symbol.value.startswith(("fastapi.", "starlette.")):
                    continue
                if not class_name.endswith("Response"):
                    continue
                findings.append(
                    _finding(
                        MAPPING_RULE_ID,
                        target.module_id,
                        call.enclosing_symbol or symbol,
                        call.id,
                        call.location,
                        "schema.router_direct_mapping",
                        class_name,
                    )
                )
        else:
            return RuleEvaluation(MAPPING_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        if findings:
            return RuleEvaluation(MAPPING_RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(MAPPING_RULE_ID, target, RuleVerdict.PASS, ())


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
            RULE_VERSION,
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
        RuleDefinition(
            MAPPING_RULE_ID,
            RULE_VERSION,
            "응답 자료 변환 경계",
            "응답 변환은 Response.from_internal에서 필드를 하나씩 명시하세요.",
            RuleTarget.MODULE,
            requirements,
            ChangeImpact.SELF,
            ResponseMappingRule(),
            ("tests/fixtures/rules/response_mapping/compliant.py",),
            ("tests/fixtures/rules/response_mapping/violation.py",),
        ),
    )
