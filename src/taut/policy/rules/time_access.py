from __future__ import annotations

from taut.configuration.catalog import AccessPath, Effect, EffectResolutionState
from taut.domain.evaluations import (
    ChangeImpact,
    RuleTarget,
    RuleTargetRef,
    RuleVerdict,
)
from taut.domain.facts import AnalysisStage
from taut.domain.findings import EvidenceItem
from taut.domain.ids import RuleId
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import (
    build_finding,
    target_uncertainty,
    unresolved_effect_evaluation,
)

RULE_ID = RuleId("TIME001")
RULE_VERSION = 2
TIME_EFFECT = Effect.TIME_NOW


class TimeAccessRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.fact_id is None:
            raise ValueError("TIME001 requires a call target")
        incomplete = target_uncertainty(RULE_ID, target, context)
        if incomplete is not None:
            return incomplete
        call = context.model.call(target.fact_id)
        uncertain = unresolved_effect_evaluation(
            RULE_ID, target, context, call.id, frozenset({TIME_EFFECT})
        )
        if uncertain is not None:
            return uncertain
        resolution = context.effect_of(call)
        if resolution.state is EffectResolutionState.SYMBOL_UNRESOLVED:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        if resolution.state is not EffectResolutionState.MATCHED:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        if TIME_EFFECT not in resolution.effects:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        if resolution.access_path is AccessPath.APPROVED_WRAPPER:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.PASS, ())
        if call.enclosing_symbol is not None:
            enclosing_entry = context.catalog.entries.get(call.enclosing_symbol)
            if (
                enclosing_entry is not None
                and enclosing_entry.access_path is AccessPath.APPROVED_WRAPPER
                and TIME_EFFECT in enclosing_entry.effects
            ):
                return RuleEvaluation(RULE_ID, target, RuleVerdict.PASS, ())
        if call.ref.symbol is None:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        symbol = call.ref.symbol.value
        finding = build_finding(
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            module_id=call.module_id,
            enclosing_symbol=call.enclosing_symbol,
            subject=call.id,
            normalized_subject=f"{symbol}:{call.id.value}",
            message_key="time.direct_access",
            arguments=(("symbol", symbol),),
            location=call.location,
            evidence=(EvidenceItem("effect", TIME_EFFECT.value), EvidenceItem("symbol", symbol)),
        )
        return RuleEvaluation(RULE_ID, target, RuleVerdict.FAIL, (finding,))


def time_rule_definition() -> RuleDefinition:
    return RuleDefinition(
        id=RULE_ID,
        behavior_version=RULE_VERSION,
        title="승인된 시간 함수 사용",
        help="직접 시간 조회 대신 저장소에서 승인한 시간 함수를 사용하세요.",
        target=RuleTarget.CALL,
        requirements=RuleRequirements(frozenset(), AnalysisStage.RESOLVED, False, False),
        change_impact=ChangeImpact.SELF,
        implementation=TimeAccessRule(),
        compliant_fixtures=("tests/fixtures/rules/time/compliant.py",),
        violation_fixtures=("tests/fixtures/rules/time/violation.py",),
    )
