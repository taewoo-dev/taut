from __future__ import annotations

from taut.configuration.catalog import Effect, EffectResolutionState
from taut.domain.evaluations import (
    ChangeImpact,
    EvaluationReason,
    RuleTarget,
    RuleTargetRef,
    RuleVerdict,
)
from taut.domain.facts import AnalysisStage, ResolutionState
from taut.domain.findings import EvidenceItem, Finding
from taut.domain.ids import RuleId
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import (
    build_finding,
    module_fact_uncertainty,
    unresolved_call_evaluation,
)

HTTP_RULE_ID = RuleId("HTTP001")
LOG_RULE_ID = RuleId("LOG001")
RULE_VERSION = 1


class HttpTimeoutRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("HTTP001 requires a module target")
        uncertainty = module_fact_uncertainty(HTTP_RULE_ID, target, context, target.module_id)
        if uncertainty is not None:
            return uncertainty
        configured = frozenset(context.policy.boundaries.http_timeout_calls)
        uncertainty = unresolved_call_evaluation(
            HTTP_RULE_ID, target, context, target.module_id, tuple(configured)
        )
        if uncertainty is not None:
            return uncertainty
        relevant = tuple(
            call
            for call in context.model.module(target.module_id).calls
            if call.ref.state is ResolutionState.RESOLVED and call.ref.symbol in configured
        )
        if not relevant:
            return RuleEvaluation(HTTP_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        findings = tuple(
            build_finding(
                rule_id=HTTP_RULE_ID,
                rule_version=RULE_VERSION,
                module_id=call.module_id,
                enclosing_symbol=call.enclosing_symbol,
                subject=call.id,
                normalized_subject=f"timeout:{call.id.value}",
                message_key="http.timeout_missing",
                arguments=(("call", call.ref.written_name),),
                location=call.location,
                evidence=(EvidenceItem("call", call.ref.written_name),),
            )
            for call in relevant
            if "timeout" not in call.keyword_names and not call.has_keyword_unpack
        )
        if findings:
            return RuleEvaluation(HTTP_RULE_ID, target, RuleVerdict.FAIL, findings)
        if any(
            "timeout" not in call.keyword_names and call.has_keyword_unpack for call in relevant
        ):
            return RuleEvaluation(
                HTTP_RULE_ID,
                target,
                RuleVerdict.INDETERMINATE,
                (),
                EvaluationReason(
                    "dynamic_keywords",
                    "Cannot statically determine whether **kwargs contains a timeout.",
                ),
            )
        return RuleEvaluation(HTTP_RULE_ID, target, RuleVerdict.PASS, ())


class ExternalCallLoggingRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("LOG001 requires a module target")
        uncertainty = module_fact_uncertainty(LOG_RULE_ID, target, context, target.module_id)
        if uncertainty is not None:
            return uncertainty
        boundaries = context.policy.boundaries
        uncertainty = unresolved_call_evaluation(
            LOG_RULE_ID,
            target,
            context,
            target.module_id,
            tuple(boundaries.logged_external_calls),
        )
        if uncertainty is not None:
            return uncertainty
        relevant = tuple(
            call
            for call in context.model.module(target.module_id).calls
            if context.indexes.is_logged_external_call(call)
            or (
                (resolution := context.effect_of(call)).state is EffectResolutionState.MATCHED
                and Effect.EXTERNAL_CALL in resolution.effects
            )
        )
        if not relevant:
            return RuleEvaluation(LOG_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        findings: list[Finding] = []
        for call in relevant:
            wrapped = context.symbol_in(
                call.enclosing_symbol, boundaries.external_call_wrappers
            ) or any(
                context_ref.state is ResolutionState.RESOLVED
                and context.symbol_in(context_ref.symbol, boundaries.external_call_wrappers)
                for context_ref in call.enclosing_contexts
            )
            if wrapped:
                continue
            findings.append(
                build_finding(
                    rule_id=LOG_RULE_ID,
                    rule_version=RULE_VERSION,
                    module_id=call.module_id,
                    enclosing_symbol=call.enclosing_symbol,
                    subject=call.id,
                    normalized_subject=f"external-log:{call.id.value}",
                    message_key="log.external_call_unwrapped",
                    arguments=(("call", call.ref.written_name),),
                    location=call.location,
                    evidence=(EvidenceItem("call", call.ref.written_name),),
                )
            )
        if findings:
            return RuleEvaluation(LOG_RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(LOG_RULE_ID, target, RuleVerdict.PASS, ())


def external_call_rule_definitions() -> tuple[RuleDefinition, RuleDefinition]:
    requirements = RuleRequirements(frozenset(), AnalysisStage.FACTS_READY, False, False)
    http = RuleDefinition(
        id=HTTP_RULE_ID,
        behavior_version=RULE_VERSION,
        title="Explicit HTTP timeout",
        help="Specify a timeout when constructing configured HTTP clients.",
        target=RuleTarget.MODULE,
        requirements=requirements,
        change_impact=ChangeImpact.SELF,
        implementation=HttpTimeoutRule(),
        compliant_fixtures=("tests/fixtures/rules/external/http_compliant.py",),
        violation_fixtures=("tests/fixtures/rules/external/http_violation.py",),
    )
    log = RuleDefinition(
        id=LOG_RULE_ID,
        behavior_version=RULE_VERSION,
        title="Structured external call logging",
        help="Run external calls inside an approved external_call context.",
        target=RuleTarget.MODULE,
        requirements=requirements,
        change_impact=ChangeImpact.SELF,
        implementation=ExternalCallLoggingRule(),
        compliant_fixtures=("tests/fixtures/rules/external/log_compliant.py",),
        violation_fixtures=("tests/fixtures/rules/external/log_violation.py",),
    )
    return http, log
