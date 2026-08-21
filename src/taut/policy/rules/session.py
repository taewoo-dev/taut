from __future__ import annotations

from taut.domain.evaluations import (
    ChangeImpact,
    EvaluationReason,
    RuleTarget,
    RuleTargetRef,
    RuleVerdict,
)
from taut.domain.facts import AnalysisStage, ExpressionSummary, ResolutionState
from taut.domain.findings import EvidenceItem, Finding
from taut.domain.ids import RuleId, SymbolId
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import build_finding, target_uncertainty, unresolved_call_evaluation

OWNER_RULE_ID = RuleId("SESSION001")
NESTED_RULE_ID = RuleId("SESSION002")
PARAMETER_RULE_ID = RuleId("SESSION003")
RULE_VERSION = 1


class SessionOwnerRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.fact_id is None or target.module_id is None:
            raise ValueError("SESSION001 requires a call target")
        incomplete = target_uncertainty(OWNER_RULE_ID, target, context)
        if incomplete is not None:
            return incomplete
        call = context.model.call(target.fact_id)
        if call.ref.state is not ResolutionState.RESOLVED:
            uncertain = unresolved_call_evaluation(
                OWNER_RULE_ID,
                target,
                context,
                call.module_id,
                tuple(context.policy.transaction_session_providers),
            )
            if uncertain is not None:
                return uncertain
            return RuleEvaluation(OWNER_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        if call.ref.state is not ResolutionState.RESOLVED or call.ref.symbol is None:
            return RuleEvaluation(OWNER_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        if call.ref.symbol not in context.policy.transaction_session_providers:
            return RuleEvaluation(OWNER_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        if call.enclosing_symbol in context.policy.transaction_session_providers:
            return RuleEvaluation(OWNER_RULE_ID, target, RuleVerdict.PASS, ())
        classification = context.classification.get(target.module_id)
        if classification.role is None:
            return RuleEvaluation(
                OWNER_RULE_ID,
                target,
                RuleVerdict.INDETERMINATE,
                (),
                EvaluationReason("missing_role", "파일의 role이 정해지지 않았습니다."),
            )
        if classification.role in context.policy.transaction_owner_roles:
            return RuleEvaluation(OWNER_RULE_ID, target, RuleVerdict.PASS, ())
        provider = call.ref.symbol.value
        finding = build_finding(
            rule_id=OWNER_RULE_ID,
            rule_version=RULE_VERSION,
            module_id=call.module_id,
            enclosing_symbol=call.enclosing_symbol,
            subject=call.id,
            normalized_subject=f"{provider}:{classification.role.value}:{call.id.value}",
            message_key="session.outside_owner",
            arguments=(("provider", provider), ("role", classification.role.value)),
            location=call.location,
            evidence=(
                EvidenceItem("provider", provider),
                EvidenceItem("role", classification.role.value),
            ),
        )
        return RuleEvaluation(OWNER_RULE_ID, target, RuleVerdict.FAIL, (finding,))


class NestedSessionRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.fact_id is None:
            raise ValueError("SESSION002 requires a call target")
        incomplete = target_uncertainty(NESTED_RULE_ID, target, context)
        if incomplete is not None:
            return incomplete
        call = context.model.call(target.fact_id)
        if call.ref.state is not ResolutionState.RESOLVED:
            uncertain = unresolved_call_evaluation(
                NESTED_RULE_ID,
                target,
                context,
                call.module_id,
                tuple(context.policy.transaction_session_providers),
            )
            if uncertain is not None:
                return uncertain
            return RuleEvaluation(NESTED_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        provider = call.ref.symbol
        if provider is None or provider not in context.policy.transaction_session_providers:
            return RuleEvaluation(NESTED_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        enclosing = next(
            (
                item.symbol
                for item in call.enclosing_contexts
                if item.symbol in context.policy.transaction_session_providers
            ),
            None,
        )
        if enclosing is None:
            return RuleEvaluation(NESTED_RULE_ID, target, RuleVerdict.PASS, ())
        finding = build_finding(
            rule_id=NESTED_RULE_ID,
            rule_version=RULE_VERSION,
            module_id=call.module_id,
            enclosing_symbol=call.enclosing_symbol,
            subject=call.id,
            normalized_subject=f"{enclosing.value}:{provider.value}:{call.id.value}",
            message_key="session.nested",
            arguments=(("provider", provider.value),),
            location=call.location,
            evidence=(
                EvidenceItem("outer_provider", enclosing.value),
                EvidenceItem("inner_provider", provider.value),
            ),
        )
        return RuleEvaluation(NESTED_RULE_ID, target, RuleVerdict.FAIL, (finding,))


def _session_annotation(
    annotation: ExpressionSummary | None,
    session_types: tuple[SymbolId, ...],
) -> SymbolId | None:
    if annotation is None:
        return None
    return next((symbol for symbol in annotation.symbols if symbol in session_types), None)


class ServiceSessionParameterRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("SESSION003 requires a module target")
        role = context.classification.get(target.module_id).role
        if role is None or role not in context.policy.boundaries.service_roles:
            return RuleEvaluation(PARAMETER_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        findings: list[Finding] = []
        for function in context.model.module(target.module_id).functions:
            session_type = next(
                (
                    symbol
                    for parameter in function.parameters
                    if (
                        symbol := _session_annotation(
                            parameter.annotation,
                            context.policy.boundaries.session_type_symbols,
                        )
                    )
                    is not None
                ),
                None,
            )
            if session_type is None:
                continue
            findings.append(
                build_finding(
                    rule_id=PARAMETER_RULE_ID,
                    rule_version=RULE_VERSION,
                    module_id=target.module_id,
                    enclosing_symbol=function.symbol_id,
                    subject=function.id,
                    normalized_subject=f"{function.symbol_id.value}:{session_type.value}",
                    message_key="session.service_parameter",
                    arguments=(("symbol", function.symbol_id.value),),
                    location=function.location,
                    evidence=(EvidenceItem("session_type", session_type.value),),
                )
            )
        verdict = RuleVerdict.FAIL if findings else RuleVerdict.PASS
        return RuleEvaluation(PARAMETER_RULE_ID, target, verdict, tuple(findings))


def session_rule_definitions() -> tuple[RuleDefinition, ...]:
    call_requirements = RuleRequirements(frozenset(), AnalysisStage.RESOLVED, False, False)
    module_requirements = RuleRequirements(frozenset(), AnalysisStage.FACTS_READY, False, False)
    return (
        RuleDefinition(
            id=OWNER_RULE_ID,
            behavior_version=RULE_VERSION,
            title="DB session 생성 위치 제한",
            help="DB session은 저장소에서 정한 transaction owner 안에서만 여세요.",
            target=RuleTarget.CALL,
            requirements=call_requirements,
            change_impact=ChangeImpact.SELF,
            implementation=SessionOwnerRule(),
            compliant_fixtures=("tests/fixtures/rules/session/compliant.py",),
            violation_fixtures=("tests/fixtures/rules/session/violation.py",),
        ),
        RuleDefinition(
            id=NESTED_RULE_ID,
            behavior_version=RULE_VERSION,
            title="DB session 중첩 금지",
            help="한 session 문맥 안에서 다른 session을 열지 마세요.",
            target=RuleTarget.CALL,
            requirements=call_requirements,
            change_impact=ChangeImpact.SELF,
            implementation=NestedSessionRule(),
            compliant_fixtures=("tests/fixtures/rules/session_nested/compliant.py",),
            violation_fixtures=("tests/fixtures/rules/session_nested/violation.py",),
        ),
        RuleDefinition(
            id=PARAMETER_RULE_ID,
            behavior_version=RULE_VERSION,
            title="Service session 인자 금지",
            help="Service는 session을 인자로 받지 말고 자기 transaction 경계를 여세요.",
            target=RuleTarget.MODULE,
            requirements=module_requirements,
            change_impact=ChangeImpact.SELF,
            implementation=ServiceSessionParameterRule(),
            compliant_fixtures=("tests/fixtures/rules/session_parameter/compliant.py",),
            violation_fixtures=("tests/fixtures/rules/session_parameter/violation.py",),
        ),
    )
