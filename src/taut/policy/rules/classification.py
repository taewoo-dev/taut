from __future__ import annotations

from taut.configuration.manifest import Zone
from taut.domain.evaluations import ChangeImpact, RuleTarget, RuleTargetRef, RuleVerdict
from taut.domain.facts import AnalysisStage
from taut.domain.findings import EvidenceItem
from taut.domain.ids import RuleId
from taut.domain.location import SourceRange
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import build_finding

RULE_ID = RuleId("ARCH000")
RULE_VERSION = 1
_ALL_ZONES = frozenset({Zone("prod"), Zone("test"), Zone("migration"), Zone("script")})


class AssignedRoleRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("ARCH000 requires a module target")
        classification = context.classification.get(target.module_id)
        if classification.role is not None:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.PASS, ())
        module = context.model.module(target.module_id).module
        finding = build_finding(
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            module_id=target.module_id,
            enclosing_symbol=None,
            subject=target.module_id,
            normalized_subject=target.module_id.value,
            message_key="role.unassigned",
            arguments=(),
            location=SourceRange(module.path, 0, 0, 0, 0),
            evidence=(EvidenceItem("zone", classification.zone.value),),
        )
        return RuleEvaluation(RULE_ID, target, RuleVerdict.FAIL, (finding,))


def classification_rule_definition() -> RuleDefinition:
    return RuleDefinition(
        id=RULE_ID,
        behavior_version=RULE_VERSION,
        title="검사 대상 파일 역할 지정",
        help="모든 검사 대상 파일을 저장소 설정의 역할 패턴에 포함하세요.",
        target=RuleTarget.MODULE,
        requirements=RuleRequirements(frozenset(), AnalysisStage.FACTS_READY, False, False),
        change_impact=ChangeImpact.SELF,
        implementation=AssignedRoleRule(),
        compliant_fixtures=("tests/fixtures/rules/classification/compliant.py",),
        violation_fixtures=("tests/fixtures/rules/classification/violation.py",),
        applies_to_zones=_ALL_ZONES,
    )
