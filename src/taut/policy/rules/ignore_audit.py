from __future__ import annotations

from taut.configuration.manifest import Zone
from taut.domain.evaluations import ChangeImpact, RuleTarget, RuleTargetRef, RuleVerdict
from taut.domain.facts import AnalysisStage
from taut.domain.ids import RuleId
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements

RULE_ID = RuleId("IGNORE001")
RULE_VERSION = 1
_ALL_ZONES = frozenset({Zone("prod"), Zone("test"), Zone("migration"), Zone("script")})


class InlineIgnoreAuditRule:
    """The actual audit runs after findings exist; this registers its public contract."""

    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        return RuleEvaluation(RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())


def ignore_audit_rule_definition() -> RuleDefinition:
    return RuleDefinition(
        id=RULE_ID,
        behavior_version=RULE_VERSION,
        title="사용되지 않은 ignore 금지",
        help="실제 위반을 숨기지 않는 ignore 주석은 제거하세요.",
        target=RuleTarget.PROJECT,
        requirements=RuleRequirements(frozenset(), AnalysisStage.DISCOVERED, False, False),
        change_impact=ChangeImpact.PROJECT,
        implementation=InlineIgnoreAuditRule(),
        compliant_fixtures=("tests/fixtures/rules/ignore/compliant.py",),
        violation_fixtures=("tests/fixtures/rules/ignore/violation.py",),
        applies_to_zones=_ALL_ZONES,
    )
