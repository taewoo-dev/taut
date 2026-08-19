from __future__ import annotations

from dataclasses import dataclass

from taut.configuration.manifest import Zone
from taut.domain.evaluations import (
    EvaluationReason,
    RuleLevel,
    RuleTarget,
    RuleTargetRef,
    RuleVerdict,
)
from taut.domain.facts import AnalysisStage, CompletenessState, ResolutionState
from taut.domain.findings import Finding
from taut.domain.issues import EngineIssue, EngineIssueKind
from taut.domain.reports import CoverageIssue, CoverageReport
from taut.policy.context import PolicyContext
from taut.policy.registry import RuleRegistry
from taut.policy.rule import RuleEvaluation, RuleRequirements
from taut.policy.scheduler import RuleScheduler

_STAGE_ORDER = {
    AnalysisStage.DISCOVERED: 0,
    AnalysisStage.PARSED: 1,
    AnalysisStage.INDEXED: 2,
    AnalysisStage.RESOLVED: 3,
    AnalysisStage.FACTS_READY: 4,
    AnalysisStage.FAILED: -1,
}


@dataclass(frozen=True)
class PolicyRunResult:
    evaluations: tuple[RuleEvaluation, ...]
    findings: tuple[Finding, ...]
    engine_issues: tuple[EngineIssue, ...]
    coverage: CoverageReport


class PolicyEngine:
    def __init__(self, registry: RuleRegistry, scheduler: RuleScheduler | None = None) -> None:
        self._registry = registry
        self._scheduler = scheduler or RuleScheduler()

    def run(self, context: PolicyContext) -> PolicyRunResult:
        evaluations: list[RuleEvaluation] = []
        issues: list[EngineIssue] = []
        enabled_rules = 0
        target_cache: dict[
            tuple[RuleTarget, frozenset[Zone]],
            tuple[RuleTargetRef, ...],
        ] = {}
        project_is_complete = all(
            context.model.module(module_id).completeness.state is CompletenessState.COMPLETE
            for module_id in context.model.modules()
        )
        for rule_id, definition in self._registry.definitions.items():
            setting = context.policy.rules.get(rule_id)
            if setting is None or setting.level is RuleLevel.OFF:
                continue
            enabled_rules += 1
            target_key = (definition.target, definition.applies_to_zones)
            targets = target_cache.get(target_key)
            if targets is None:
                targets = self._scheduler.targets_for(definition, context)
                target_cache[target_key] = targets
            for target in targets:
                reason = self._missing_requirement(
                    definition.requirements,
                    target,
                    context,
                    project_is_complete,
                )
                if reason is not None:
                    evaluations.append(
                        RuleEvaluation(
                            rule_id,
                            target,
                            RuleVerdict.INDETERMINATE,
                            (),
                            reason,
                        )
                    )
                    continue
                try:
                    evaluation = definition.implementation.evaluate(target, context)
                    if evaluation.rule_id != rule_id or evaluation.target != target:
                        raise ValueError("rule returned a mismatched id or target")
                    evaluations.append(evaluation)
                except Exception as error:
                    evaluations.append(
                        RuleEvaluation(
                            rule_id,
                            target,
                            RuleVerdict.INDETERMINATE,
                            (),
                            EvaluationReason(
                                "rule_failure",
                                "규칙 실행 중 오류가 발생해 판단하지 못했습니다.",
                            ),
                        )
                    )
                    issues.append(
                        EngineIssue(
                            code="RULE_FAILURE",
                            kind=EngineIssueKind.RULE_FAILURE,
                            message=f"규칙 {rule_id.value} 실행을 완료하지 못했습니다.",
                            location=None,
                            cause=error.__class__.__name__,
                        )
                    )
        # Registry iteration and scheduler targets are already deterministic and sorted.
        ordered = tuple(evaluations)
        findings = tuple(
            sorted(
                (finding for evaluation in ordered for finding in evaluation.findings),
                key=lambda finding: (
                    finding.primary_location.path.value,
                    finding.primary_location.start_line,
                    finding.primary_location.start_column,
                    finding.rule_id.value,
                    finding.fingerprint.value,
                ),
            )
        )
        coverage = _coverage(enabled_rules, ordered, context)
        return PolicyRunResult(ordered, findings, tuple(issues), coverage)

    def _missing_requirement(
        self,
        requirements: RuleRequirements,
        target: RuleTargetRef,
        context: PolicyContext,
        project_is_complete: bool,
    ) -> EvaluationReason | None:
        if requirements.capabilities:
            return EvaluationReason(
                "missing_capability",
                "규칙에 필요한 추가 분석 자료가 없습니다.",
            )
        if requirements.needs_complete_project and not project_is_complete:
            return EvaluationReason(
                "incomplete_project",
                "프로젝트 전체 분석이 완성되지 않았습니다.",
            )
        if target.kind is not RuleTarget.PROJECT and target.module_id is not None:
            completeness = context.model.module(target.module_id).completeness
            if _STAGE_ORDER[completeness.stage] < _STAGE_ORDER[requirements.minimum_stage]:
                return EvaluationReason(
                    "insufficient_analysis",
                    "규칙에 필요한 분석 단계까지 완료되지 않았습니다.",
                )
        if requirements.needs_resolved_symbols and target.fact_id is not None:
            call = context.model.call(target.fact_id)
            if call.ref.state is not ResolutionState.RESOLVED:
                return EvaluationReason(
                    "unresolved_symbol",
                    "호출 대상을 정확히 확인하지 못했습니다.",
                )
        return None


def _coverage(
    enabled_rules: int,
    evaluations: tuple[RuleEvaluation, ...],
    context: PolicyContext,
) -> CoverageReport:
    verdicts = tuple(evaluation.verdict for evaluation in evaluations)
    skipped = tuple(
        CoverageIssue(
            evaluation.rule_id,
            evaluation.target,
            evaluation.reason,
            context.policy.setting(evaluation.rule_id).level,
        )
        for evaluation in evaluations
        if evaluation.verdict is RuleVerdict.INDETERMINATE and evaluation.reason is not None
    )
    return CoverageReport(
        enabled_rules=enabled_rules,
        total_targets=len(evaluations),
        passed=verdicts.count(RuleVerdict.PASS),
        failed=verdicts.count(RuleVerdict.FAIL),
        not_applicable=verdicts.count(RuleVerdict.NOT_APPLICABLE),
        indeterminate=verdicts.count(RuleVerdict.INDETERMINATE),
        skipped=skipped,
    )
