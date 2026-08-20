from __future__ import annotations

from fnmatch import fnmatchcase

from taut.configuration.effective_policy import ImportBoundary
from taut.domain.evaluations import (
    ChangeImpact,
    EvaluationReason,
    RuleTarget,
    RuleTargetRef,
    RuleVerdict,
)
from taut.domain.facts import AnalysisStage, CallFact, GuardKind, ImportFact, ResolutionState
from taut.domain.findings import EvidenceItem, Finding
from taut.domain.ids import ModuleId, RuleId
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import (
    build_finding,
    module_fact_uncertainty,
    unresolved_call_evaluation,
)

RULE_ID = RuleId("BOUNDARY001")
RULE_VERSION = 2


def _matches_prefix(import_fact: ImportFact, prefix: ModuleId) -> bool:
    imported = import_fact.imported_module_name
    return imported == prefix.value or imported.startswith(f"{prefix.value}.")


def _finding(
    import_fact: ImportFact,
    boundary: ImportBoundary,
    prefix: ModuleId,
    role: str,
) -> Finding:
    imported = import_fact.imported_module_name
    return build_finding(
        rule_id=RULE_ID,
        rule_version=RULE_VERSION,
        module_id=import_fact.module_id,
        enclosing_symbol=import_fact.enclosing_symbol,
        subject=import_fact.id,
        normalized_subject=(
            f"{boundary.name}:{role}:{prefix.value}:{imported}:{import_fact.id.value}"
        ),
        message_key="boundary.forbidden_import",
        arguments=(("role", role), ("imported", imported), ("boundary", boundary.name)),
        location=import_fact.location,
        evidence=(
            EvidenceItem("boundary", boundary.name),
            EvidenceItem("role", role),
            EvidenceItem("imported", imported),
            EvidenceItem("forbidden_prefix", prefix.value),
        ),
    )


def _matches_call(call: CallFact, pattern: str) -> bool:
    return bool(
        call.ref.state is ResolutionState.RESOLVED
        and call.ref.symbol is not None
        and fnmatchcase(call.ref.symbol.value, pattern)
    )


def _call_finding(
    call: CallFact,
    boundary: ImportBoundary,
    pattern: str,
    role: str,
) -> Finding:
    return build_finding(
        rule_id=RULE_ID,
        rule_version=RULE_VERSION,
        module_id=call.module_id,
        enclosing_symbol=call.enclosing_symbol,
        subject=call.id,
        normalized_subject=f"{boundary.name}:{role}:{pattern}:{call.id.value}",
        message_key="boundary.forbidden_call",
        arguments=(("role", role), ("call", call.ref.written_name), ("boundary", boundary.name)),
        location=call.location,
        evidence=(
            EvidenceItem("boundary", boundary.name),
            EvidenceItem("role", role),
            EvidenceItem("call", call.ref.written_name),
            EvidenceItem("forbidden_pattern", pattern),
        ),
    )


class ForbiddenImportRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("BOUNDARY001 requires a module target")
        if not context.policy.import_boundaries:
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
        boundaries = tuple(
            boundary
            for boundary in context.policy.import_boundaries
            if classification.role in boundary.roles
        )
        if not boundaries:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        uncertainty = module_fact_uncertainty(RULE_ID, target, context, target.module_id)
        if uncertainty is not None:
            return uncertainty
        uncertainty = unresolved_call_evaluation(
            RULE_ID,
            target,
            context,
            target.module_id,
            tuple(call for boundary in boundaries for call in boundary.forbidden_calls),
        )
        if uncertainty is not None:
            return uncertainty
        findings: list[Finding] = []
        seen: set[tuple[str, str, int, int]] = set()
        for import_fact in context.model.module(target.module_id).imports:
            if import_fact.context.guard is GuardKind.TYPE_CHECKING_ONLY:
                continue
            for boundary in boundaries:
                prefix = next(
                    (
                        item
                        for item in boundary.forbidden_imports
                        if _matches_prefix(import_fact, item)
                    ),
                    None,
                )
                if prefix is not None:
                    key = (
                        boundary.name,
                        prefix.value,
                        import_fact.location.start_line,
                        import_fact.location.start_column,
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        _finding(import_fact, boundary, prefix, classification.role.value)
                    )
        for call in context.model.module(target.module_id).calls:
            for boundary in boundaries:
                pattern = next(
                    (item for item in boundary.forbidden_calls if _matches_call(call, item)),
                    None,
                )
                if pattern is not None:
                    findings.append(
                        _call_finding(call, boundary, pattern, classification.role.value)
                    )
        if findings:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(RULE_ID, target, RuleVerdict.PASS, ())


def boundary_rule_definition() -> RuleDefinition:
    return RuleDefinition(
        id=RULE_ID,
        behavior_version=RULE_VERSION,
        title="역할별 금지 import와 호출",
        help="이 역할에서 금지한 모듈과 함수를 직접 사용하지 말고 허용된 계층을 거치세요.",
        target=RuleTarget.MODULE,
        requirements=RuleRequirements(frozenset(), AnalysisStage.FACTS_READY, False, False),
        change_impact=ChangeImpact.SELF,
        implementation=ForbiddenImportRule(),
        compliant_fixtures=("tests/fixtures/rules/boundary/compliant.py",),
        violation_fixtures=("tests/fixtures/rules/boundary/violation.py",),
    )
