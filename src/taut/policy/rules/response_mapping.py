from __future__ import annotations

from taut.domain.evaluations import ChangeImpact, RuleTarget, RuleTargetRef, RuleVerdict
from taut.domain.facts import AnalysisStage, CallFact, ClassFact
from taut.domain.findings import Finding
from taut.domain.ids import FactId, RuleId, SymbolId
from taut.domain.location import SourceRange
from taut.domain.symbol_contracts import ContractKind
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import build_policy_finding, target_uncertainty

RULE_ID = RuleId("SCHEMA003")
RULE_VERSION = 2
_BULK_MAPPING_OPERATIONS = frozenset({"asdict", "dict", "model_dump", "model_validate", "vars"})


class ResponseMappingRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("SCHEMA003 requires a module target")
        role = context.classification.get(target.module_id).role
        if (
            role not in context.policy.code.schema_roles
            and role not in context.policy.code.router_roles
        ):
            return RuleEvaluation(RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        uncertainty = target_uncertainty(RULE_ID, target, context)
        if uncertainty is not None:
            return uncertainty
        module = context.model.module(target.module_id)
        findings: list[Finding] = []
        if role in context.policy.code.schema_roles:
            functions = {function.symbol_id: function for function in module.functions}
            for class_fact in module.classes:
                if not context.symbol_contracts.has(class_fact, ContractKind.RESPONSE):
                    continue
                mapper_name = context.policy.code.response_mapper_name
                method_symbol = SymbolId(f"{class_fact.symbol_id.value}.{mapper_name}")
                method = functions.get(method_symbol)
                if method is None:
                    findings.append(
                        _finding(
                            target,
                            class_fact.symbol_id,
                            class_fact.id,
                            class_fact.location,
                            "schema.mapper_missing",
                            mapper_name,
                        )
                    )
                    continue
                if not any(
                    decorator.written_name == "classmethod"
                    or (
                        decorator.symbol is not None
                        and decorator.symbol.value in {"builtins.classmethod", "classmethod"}
                    )
                    for decorator in method.decorators
                ):
                    findings.append(
                        _finding(
                            target,
                            class_fact.symbol_id,
                            method.id,
                            method.location,
                            "schema.mapper_not_classmethod",
                            mapper_name,
                        )
                    )
                if len(method.parameters) < 2 or method.parameters[1].annotation is None:
                    findings.append(
                        _finding(
                            target,
                            class_fact.symbol_id,
                            method.id,
                            method.location,
                            "schema.mapper_input_untyped",
                            mapper_name,
                        )
                    )
                if method.return_annotation is None:
                    findings.append(
                        _finding(
                            target,
                            class_fact.symbol_id,
                            method.id,
                            method.location,
                            "schema.mapper_return_untyped",
                            mapper_name,
                        )
                    )
                findings.extend(
                    _finding(
                        target,
                        class_fact.symbol_id,
                        call.id,
                        call.location,
                        "schema.bulk_mapping",
                        call.ref.written_name,
                    )
                    for call in module.calls
                    if call.enclosing_symbol == method_symbol
                    and _is_bulk_mapping(call, class_fact.symbol_id)
                )
                findings.extend(
                    _finding(
                        target,
                        class_fact.symbol_id,
                        call.id,
                        call.location,
                        "schema.bulk_mapping",
                        sorted(summary.bulk_mapping_operations)[0],
                    )
                    for call in module.calls
                    if call.enclosing_symbol == method_symbol
                    and (summary := context.function_summary(call.ref.symbol)) is not None
                    and summary.bulk_mapping_operations
                    and _feeds_response_construction(call, module.calls, class_fact.symbol_id)
                )
        else:
            findings.extend(_router_findings(target, context))
        if findings:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(RULE_ID, target, RuleVerdict.PASS, ())


def _is_bulk_mapping(call: CallFact, response_symbol: SymbolId) -> bool:
    if call.ref.symbol is not None and (
        call.ref.symbol.value.rsplit(".", maxsplit=1)[-1] in _BULK_MAPPING_OPERATIONS
    ):
        return True
    if not call.has_keyword_unpack:
        return False
    written = call.ref.written_name
    if written in {"cls", response_symbol.value.rsplit(".", maxsplit=1)[-1]}:
        return True
    symbol = call.ref.symbol
    return symbol == response_symbol or (
        symbol is not None
        and symbol.value.rsplit(".", maxsplit=1)[-1].endswith(("Response", "ResponseModel"))
    )


def _feeds_response_construction(
    call: CallFact,
    calls: tuple[CallFact, ...],
    response_symbol: SymbolId,
) -> bool:
    parent_id = call.context.parent_fact_id
    return parent_id is not None and any(
        parent.id == parent_id and _is_bulk_mapping(parent, response_symbol) for parent in calls
    )


def _finding(
    target: RuleTargetRef,
    symbol: SymbolId,
    subject: FactId,
    location: SourceRange,
    key: str,
    argument: str,
) -> Finding:
    assert target.module_id is not None
    return build_policy_finding(
        RULE_ID,
        target.module_id,
        symbol,
        subject,
        location,
        key,
        argument,
        rule_version=RULE_VERSION,
    )


def _router_findings(target: RuleTargetRef, context: PolicyContext) -> tuple[Finding, ...]:
    assert target.module_id is not None
    return tuple(
        build_policy_finding(
            RULE_ID,
            target.module_id,
            call.enclosing_symbol or symbol,
            call.id,
            call.location,
            "schema.router_direct_mapping",
            class_name,
            rule_version=RULE_VERSION,
        )
        for call in context.model.module(target.module_id).calls
        if (symbol := call.ref.symbol) is not None
        and not symbol.value.startswith(("fastapi.", "starlette."))
        and (class_name := symbol.value.rsplit(".", maxsplit=1)[-1])
        and (
            (
                (class_fact := _class_for_symbol(symbol, context)) is not None
                and context.symbol_contracts.has(class_fact, ContractKind.RESPONSE)
            )
            or class_name.endswith(("Response", "ResponseModel"))
        )
    )


def _class_for_symbol(symbol: SymbolId, context: PolicyContext) -> ClassFact | None:
    return context.indexes.class_for(context.model, symbol)


def response_mapping_rule_definition() -> RuleDefinition:
    return RuleDefinition(
        RULE_ID,
        RULE_VERSION,
        "응답 자료 변환 경계",
        "응답 변환은 설정한 Response mapper에서 필드를 하나씩 명시하세요.",
        RuleTarget.MODULE,
        RuleRequirements(frozenset(), AnalysisStage.FACTS_READY, False, False),
        ChangeImpact.SELF,
        ResponseMappingRule(),
        ("tests/fixtures/rules/response_mapping/compliant.py",),
        ("tests/fixtures/rules/response_mapping/violation.py",),
    )
