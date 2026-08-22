from __future__ import annotations

from taut.configuration.catalog import EffectResolutionState
from taut.configuration.manifest import Zone
from taut.domain.evaluations import (
    ChangeImpact,
    EvaluationReason,
    RuleLevel,
    RuleTarget,
    RuleTargetRef,
    RuleVerdict,
)
from taut.domain.facts import AnalysisStage, ResolutionState
from taut.domain.findings import EvidenceItem
from taut.domain.ids import RuleId
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import build_finding, target_uncertainty

RULE_ID = RuleId("CAT001")
RULE_VERSION = 1
_ALL_ZONES = frozenset({Zone("prod"), Zone("test"), Zone("migration"), Zone("script")})


class RiskyCatalogCoverageRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.fact_id is None:
            raise ValueError("CAT001 requires a call target")
        incomplete = target_uncertainty(RULE_ID, target, context)
        if incomplete is not None:
            return incomplete
        call = context.model.call(target.fact_id)
        if call.ref.state is not ResolutionState.RESOLVED or call.ref.symbol is None:
            prefixes = context.policy.security.risky_symbol_prefixes
            if any(
                candidate.value.startswith(prefix)
                for candidate in call.ref.candidates
                for prefix in prefixes
            ):
                return RuleEvaluation(
                    RULE_ID,
                    target,
                    RuleVerdict.INDETERMINATE,
                    (),
                    EvaluationReason(
                        "uncertain_symbol", "위험 호출의 symbol을 확정하지 못했습니다."
                    ),
                )
            return RuleEvaluation(RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        resolution = context.effect_of(call)
        if resolution.state is not EffectResolutionState.NO_MATCH:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.PASS, ())
        symbol = call.ref.symbol.value
        if not any(
            symbol.startswith(prefix) for prefix in context.policy.security.risky_symbol_prefixes
        ):
            return RuleEvaluation(RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        finding = build_finding(
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            module_id=call.module_id,
            enclosing_symbol=call.enclosing_symbol,
            subject=call.id,
            normalized_subject=f"{symbol}:{call.id.value}",
            message_key="catalog.unknown_risky_call",
            arguments=(("call", symbol),),
            location=call.location,
            evidence=(EvidenceItem("symbol", symbol),),
        )
        return RuleEvaluation(RULE_ID, target, RuleVerdict.FAIL, (finding,))


def catalog_coverage_rule_definition() -> RuleDefinition:
    return RuleDefinition(
        id=RULE_ID,
        behavior_version=RULE_VERSION,
        title="위험 함수 목록 누락 표시",
        help="호출의 위험 종류를 effect 목록에 등록하거나 안전함을 검토하세요.",
        target=RuleTarget.CALL,
        requirements=RuleRequirements(frozenset(), AnalysisStage.RESOLVED, False, False),
        change_impact=ChangeImpact.SELF,
        implementation=RiskyCatalogCoverageRule(),
        compliant_fixtures=("tests/fixtures/rules/catalog/compliant.py",),
        violation_fixtures=("tests/fixtures/rules/catalog/violation.py",),
        applies_to_zones=_ALL_ZONES,
        default_level=RuleLevel.ADVISORY,
    )
