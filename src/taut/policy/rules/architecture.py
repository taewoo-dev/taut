from __future__ import annotations

from taut.domain.evaluations import (
    ChangeImpact,
    RuleTarget,
    RuleTargetRef,
    RuleVerdict,
)
from taut.domain.facts import AnalysisStage
from taut.domain.findings import EvidenceItem, Finding, RelatedLocation
from taut.domain.ids import ModuleId, RuleId
from taut.domain.location import SourceRange
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import (
    build_finding,
    module_fact_uncertainty,
    project_fact_uncertainty,
)

IMPORT_RULE_ID = RuleId("ARCH001")
CYCLE_RULE_ID = RuleId("ARCH002")
RULE_VERSION = 2


def _module_location(module_id: ModuleId, context: PolicyContext) -> SourceRange:
    path = context.model.module(module_id).module.path
    return SourceRange(path, 0, 0, 0, 0)


class ImportDirectionRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("ARCH001 requires a module target")
        source_classification = context.classification.get(target.module_id)
        if source_classification.role is None:
            return RuleEvaluation(IMPORT_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        uncertainty = module_fact_uncertainty(
            IMPORT_RULE_ID, target, context, target.module_id, calls=False, references=False
        )
        if uncertainty is not None:
            return uncertainty
        allowed = context.policy.allowed_imports.get(source_classification.role, frozenset())
        findings: list[Finding] = []
        for imported_module in context.model.imports_of(target.module_id):
            target_classification = context.classification.get(imported_module)
            if target_classification.role is None:
                continue
            if target_classification.role in allowed:
                continue
            location = _import_location(target.module_id, imported_module, context)
            findings.append(
                build_finding(
                    rule_id=IMPORT_RULE_ID,
                    rule_version=RULE_VERSION,
                    module_id=target.module_id,
                    enclosing_symbol=None,
                    subject=target.module_id,
                    normalized_subject=(
                        f"{source_classification.role.value}->"
                        f"{target_classification.role.value}:{imported_module.value}"
                    ),
                    message_key="architecture.import_direction",
                    arguments=(
                        ("source_role", source_classification.role.value),
                        ("target_role", target_classification.role.value),
                        ("target_module", imported_module.value),
                    ),
                    location=location,
                    evidence=(
                        EvidenceItem("source_role", source_classification.role.value),
                        EvidenceItem("target_role", target_classification.role.value),
                    ),
                )
            )
        if findings:
            return RuleEvaluation(IMPORT_RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(IMPORT_RULE_ID, target, RuleVerdict.PASS, ())


def _import_location(
    source: ModuleId,
    target: ModuleId,
    context: PolicyContext,
) -> SourceRange:
    for edge in context.model.import_edges_of(source):
        if edge.target == target and not edge.is_type_only:
            return edge.location
    return _module_location(source, context)


class ImportCycleRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        uncertainty = project_fact_uncertainty(CYCLE_RULE_ID, target, context)
        if uncertainty is not None:
            return uncertainty
        findings: list[Finding] = []
        for cycle in context.model.import_cycles():
            first = cycle.modules[0]
            cycle_text = " -> ".join(
                (*[module.value for module in cycle.modules], cycle.modules[0].value)
            )
            related = tuple(
                RelatedLocation(edge.location, f"{edge.importer.value} -> {edge.target.value}")
                for edge in cycle.edges[1:]
            )
            location = cycle.edges[0].location if cycle.edges else _module_location(first, context)
            findings.append(
                build_finding(
                    rule_id=CYCLE_RULE_ID,
                    rule_version=RULE_VERSION,
                    module_id=first,
                    enclosing_symbol=None,
                    subject=first,
                    normalized_subject=cycle_text,
                    message_key="architecture.import_cycle",
                    arguments=(("cycle", cycle_text),),
                    location=location,
                    evidence=(
                        EvidenceItem("modules", tuple(m.value for m in cycle.modules)),
                        EvidenceItem(
                            "edges",
                            tuple(
                                f"{edge.importer.value}->{edge.target.value}"
                                for edge in cycle.edges
                            ),
                        ),
                    ),
                    related_locations=related,
                )
            )
        if findings:
            return RuleEvaluation(CYCLE_RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(CYCLE_RULE_ID, target, RuleVerdict.PASS, ())


def architecture_rule_definitions() -> tuple[RuleDefinition, RuleDefinition]:
    import_rule = RuleDefinition(
        id=IMPORT_RULE_ID,
        behavior_version=RULE_VERSION,
        title="import 방향 제한",
        help="manifest에서 허용한 role 방향으로만 내부 모듈을 import하세요.",
        target=RuleTarget.MODULE,
        requirements=RuleRequirements(frozenset(), AnalysisStage.FACTS_READY, False, False),
        change_impact=ChangeImpact.DEPENDENTS,
        implementation=ImportDirectionRule(),
        compliant_fixtures=("tests/fixtures/rules/architecture/compliant",),
        violation_fixtures=("tests/fixtures/rules/architecture/direction_violation",),
    )
    cycle_rule = RuleDefinition(
        id=CYCLE_RULE_ID,
        behavior_version=RULE_VERSION,
        title="import 순환 금지",
        help="서로 다시 돌아오는 내부 import 연결을 끊으세요.",
        target=RuleTarget.PROJECT,
        requirements=RuleRequirements(frozenset(), AnalysisStage.INDEXED, False, True),
        change_impact=ChangeImpact.PROJECT,
        implementation=ImportCycleRule(),
        compliant_fixtures=("tests/fixtures/rules/architecture/compliant",),
        violation_fixtures=("tests/fixtures/rules/architecture/cycle_violation",),
    )
    return import_rule, cycle_rule
