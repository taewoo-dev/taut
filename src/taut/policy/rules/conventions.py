from __future__ import annotations

from taut.configuration.manifest import Zone
from taut.domain.evaluations import (
    ChangeImpact,
    EvaluationReason,
    RuleTarget,
    RuleTargetRef,
    RuleVerdict,
)
from taut.domain.facts import AnalysisStage, ImportFact, ImportIntent
from taut.domain.findings import EvidenceItem, Finding
from taut.domain.ids import ModuleId, RuleId
from taut.domain.location import SourceRange
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import build_finding, module_fact_uncertainty

IMPORT_RULE_ID = RuleId("IMPORT001")
SIZE_RULE_ID = RuleId("SIZE001")
IMPORT_RULE_VERSION = 2
SIZE_RULE_VERSION = 1


_ALL_ZONES = frozenset({Zone("prod"), Zone("test"), Zone("migration"), Zone("script")})


class ImportPlacementRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("IMPORT001 requires a module target")
        uncertainty = module_fact_uncertainty(IMPORT_RULE_ID, target, context, target.module_id)
        if uncertainty is not None:
            return uncertainty
        module = context.model.module(target.module_id)
        findings: list[Finding] = []
        seen_statements: set[tuple[str, int, int, int, int, str, str]] = set()
        for import_fact in module.imports:
            if import_fact.intent is ImportIntent.OPTIONAL_DEPENDENCY:
                continue
            violation: str | None = None
            if import_fact.enclosing_symbol is not None:
                if _breaks_eager_import_cycle(import_fact, context):
                    continue
                violation = "local"
            elif import_fact.relative_level > 0 and not module.module.is_package:
                violation = "relative"
            if violation is None:
                continue
            location = import_fact.location
            statement_key = (
                location.path.value,
                location.start_line,
                location.start_column,
                location.end_line,
                location.end_column,
                violation,
                import_fact.imported_module_name,
            )
            if statement_key in seen_statements:
                continue
            seen_statements.add(statement_key)
            findings.append(
                build_finding(
                    rule_id=IMPORT_RULE_ID,
                    rule_version=IMPORT_RULE_VERSION,
                    module_id=target.module_id,
                    enclosing_symbol=import_fact.enclosing_symbol,
                    subject=import_fact.id,
                    normalized_subject=f"{violation}:{import_fact.id.value}",
                    message_key=f"import.{violation}_import",
                    arguments=(("imported", import_fact.imported_module_name),),
                    location=import_fact.location,
                    evidence=(
                        EvidenceItem("kind", violation),
                        EvidenceItem("imported", import_fact.imported_module_name),
                    ),
                )
            )
        if findings:
            return RuleEvaluation(IMPORT_RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(IMPORT_RULE_ID, target, RuleVerdict.PASS, ())


def _breaks_eager_import_cycle(import_fact: ImportFact, context: PolicyContext) -> bool:
    edge = next(
        (
            candidate
            for candidate in context.model.import_edges_of(import_fact.module_id)
            if candidate.occurrence_id == import_fact.id and candidate.is_deferred_runtime
        ),
        None,
    )
    if edge is None:
        return False
    pending = [edge.target]
    visited: set[ModuleId] = set()
    while pending:
        module_id = pending.pop()
        if module_id == edge.importer:
            return True
        if module_id in visited:
            continue
        visited.add(module_id)
        pending.extend(
            candidate.target
            for candidate in context.model.import_edges_of(module_id)
            if candidate.is_eager_runtime
        )
    return False


class FileSizeRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("SIZE001 requires a module target")
        uncertainty = module_fact_uncertainty(SIZE_RULE_ID, target, context, target.module_id)
        if uncertainty is not None:
            return uncertainty
        classification = context.classification.get(target.module_id)
        if classification.role is None:
            return RuleEvaluation(
                SIZE_RULE_ID,
                target,
                RuleVerdict.INDETERMINATE,
                (),
                EvaluationReason("missing_role", "파일의 role이 정해지지 않았습니다."),
            )
        maximum = context.policy.max_lines_by_role.get(
            classification.role, context.policy.default_max_lines
        )
        module = context.model.module(target.module_id).module
        if module.line_count <= maximum:
            return RuleEvaluation(SIZE_RULE_ID, target, RuleVerdict.PASS, ())
        location = SourceRange(module.path, 0, 0, 0, 0)
        finding = build_finding(
            rule_id=SIZE_RULE_ID,
            rule_version=SIZE_RULE_VERSION,
            module_id=target.module_id,
            enclosing_symbol=None,
            subject=target.module_id,
            normalized_subject=f"{classification.role.value}:{module.line_count}:{maximum}",
            message_key="size.file_too_large",
            arguments=(("lines", module.line_count), ("maximum", maximum)),
            location=location,
            evidence=(
                EvidenceItem("role", classification.role.value),
                EvidenceItem("lines", module.line_count),
                EvidenceItem("maximum", maximum),
            ),
        )
        return RuleEvaluation(SIZE_RULE_ID, target, RuleVerdict.FAIL, (finding,))


def convention_rule_definitions() -> tuple[RuleDefinition, RuleDefinition]:
    import_rule = RuleDefinition(
        id=IMPORT_RULE_ID,
        behavior_version=IMPORT_RULE_VERSION,
        title="import 위치 제한",
        help="import는 파일 상단에 두고, 패키지 초기화 파일 밖에서는 절대 import를 사용하세요.",
        target=RuleTarget.MODULE,
        requirements=RuleRequirements(frozenset(), AnalysisStage.FACTS_READY, False, False),
        change_impact=ChangeImpact.SELF,
        implementation=ImportPlacementRule(),
        compliant_fixtures=("tests/fixtures/rules/import/compliant.py",),
        violation_fixtures=("tests/fixtures/rules/import/violation.py",),
        applies_to_zones=_ALL_ZONES,
    )
    size_rule = RuleDefinition(
        id=SIZE_RULE_ID,
        behavior_version=SIZE_RULE_VERSION,
        title="파일 최대 줄 수",
        help="역할별 최대 줄 수보다 큰 파일은 책임 단위로 나누세요.",
        target=RuleTarget.MODULE,
        requirements=RuleRequirements(frozenset(), AnalysisStage.FACTS_READY, False, False),
        change_impact=ChangeImpact.SELF,
        implementation=FileSizeRule(),
        compliant_fixtures=("tests/fixtures/rules/size/compliant.py",),
        violation_fixtures=("tests/fixtures/rules/size/violation.py",),
        applies_to_zones=_ALL_ZONES,
    )
    return import_rule, size_rule
