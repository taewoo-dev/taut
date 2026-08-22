from __future__ import annotations

from taut.configuration.catalog import AccessPath, Effect, EffectResolutionState
from taut.configuration.manifest import Zone
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

RULE_ID = RuleId("ASYNC001")
RULE_VERSION = 1
_ALL_ZONES = frozenset({Zone("prod"), Zone("test"), Zone("migration"), Zone("script")})


class BlockingCallInAsyncRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.fact_id is None:
            raise ValueError("ASYNC001 requires a call target")
        incomplete = target_uncertainty(RULE_ID, target, context)
        if incomplete is not None:
            return incomplete
        call = context.model.call(target.fact_id)
        enclosing = (
            context.indexes.functions_by_symbol.get(call.enclosing_symbol)
            if call.enclosing_symbol
            else None
        )
        if enclosing is None or not enclosing.is_async:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        uncertain = unresolved_effect_evaluation(
            RULE_ID, target, context, call.id, frozenset({Effect.IO_BLOCKING})
        )
        if uncertain is not None:
            return uncertain
        resolution = context.effect_of(call)
        if resolution.state is EffectResolutionState.SYMBOL_UNRESOLVED:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        if resolution.state is not EffectResolutionState.MATCHED:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        if Effect.IO_BLOCKING not in resolution.effects:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        if resolution.access_path is AccessPath.APPROVED_WRAPPER:
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
            message_key="async.blocking_call",
            arguments=(("call", symbol),),
            location=call.location,
            evidence=(EvidenceItem("effect", Effect.IO_BLOCKING.value),),
        )
        return RuleEvaluation(RULE_ID, target, RuleVerdict.FAIL, (finding,))


def async_safety_rule_definition() -> RuleDefinition:
    return RuleDefinition(
        id=RULE_ID,
        behavior_version=RULE_VERSION,
        title="async 함수의 동기 호출 금지",
        help="비동기 함수나 스레드 실행 경로를 사용해 event loop가 멈추지 않게 하세요.",
        target=RuleTarget.CALL,
        requirements=RuleRequirements(frozenset(), AnalysisStage.RESOLVED, False, False),
        change_impact=ChangeImpact.SELF,
        implementation=BlockingCallInAsyncRule(),
        compliant_fixtures=("tests/fixtures/rules/async_safety/compliant.py",),
        violation_fixtures=("tests/fixtures/rules/async_safety/violation.py",),
        applies_to_zones=_ALL_ZONES,
    )
