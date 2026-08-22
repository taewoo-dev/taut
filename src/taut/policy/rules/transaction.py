from __future__ import annotations

from taut.configuration.catalog import Effect, EffectResolutionState
from taut.domain.evaluations import (
    ChangeImpact,
    EvaluationReason,
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

RULE_ID = RuleId("TX001")
RULE_VERSION = 3
TRANSACTION_EFFECTS = frozenset({Effect.TX_COMMIT, Effect.TX_ROLLBACK})


class TransactionOwnerRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.fact_id is None or target.module_id is None:
            raise ValueError("TX001 requires a call target")
        incomplete = target_uncertainty(RULE_ID, target, context)
        if incomplete is not None:
            return incomplete
        call = context.model.call(target.fact_id)
        uncertain = unresolved_effect_evaluation(
            RULE_ID, target, context, call.id, TRANSACTION_EFFECTS
        )
        if uncertain is not None:
            return uncertain
        resolution = context.effect_of(call)
        if resolution.state is EffectResolutionState.SYMBOL_UNRESOLVED:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        if resolution.state is not EffectResolutionState.MATCHED:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        matched = TRANSACTION_EFFECTS.intersection(resolution.effects)
        if not matched:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        classification = context.classification.get(target.module_id)
        if classification.role is None:
            return RuleEvaluation(
                RULE_ID,
                target,
                RuleVerdict.INDETERMINATE,
                (),
                EvaluationReason("missing_role", "파일의 role이 정해지지 않았습니다."),
            )
        if classification.role in context.policy.transaction_owner_roles:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.PASS, ())
        effect = sorted(item.value for item in matched)[0]
        finding = build_finding(
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            module_id=call.module_id,
            enclosing_symbol=call.enclosing_symbol,
            subject=call.id,
            normalized_subject=f"{effect}:{classification.role.value}:{call.id.value}",
            message_key="transaction.outside_owner",
            arguments=(("effect", effect), ("role", classification.role.value)),
            location=call.location,
            evidence=(
                EvidenceItem("effect", effect),
                EvidenceItem("role", classification.role.value),
            ),
        )
        return RuleEvaluation(RULE_ID, target, RuleVerdict.FAIL, (finding,))


def transaction_rule_definition() -> RuleDefinition:
    return RuleDefinition(
        id=RULE_ID,
        behavior_version=RULE_VERSION,
        title="transaction 종료 위치 제한",
        help="commit과 rollback은 저장소에서 정한 transaction owner에서만 실행하세요.",
        target=RuleTarget.CALL,
        requirements=RuleRequirements(frozenset(), AnalysisStage.RESOLVED, False, False),
        change_impact=ChangeImpact.SELF,
        implementation=TransactionOwnerRule(),
        compliant_fixtures=("tests/fixtures/rules/transaction/compliant.py",),
        violation_fixtures=("tests/fixtures/rules/transaction/violation.py",),
    )
