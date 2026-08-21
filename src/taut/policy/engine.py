from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from taut.configuration.manifest import Zone
from taut.domain.evaluations import (
    ChangeImpact,
    EvaluationReason,
    RuleLevel,
    RuleTarget,
    RuleTargetRef,
    RuleVerdict,
)
from taut.domain.facts import AnalysisStage, CompletenessState, ResolutionState
from taut.domain.findings import Finding
from taut.domain.ids import ModuleId, RuleId
from taut.domain.issues import EngineIssue, EngineIssueKind
from taut.domain.reports import CoverageIssue, CoverageReport
from taut.policy.context import PolicyContext
from taut.policy.registry import RuleRegistry
from taut.policy.rule import RuleEvaluation, RuleRequirements
from taut.policy.scheduler import RuleScheduler

_EvaluationKey = tuple[RuleId, RuleTargetRef]
_RegistryEntry = tuple[object, ...]
_RegistryIdentity = tuple[_RegistryEntry, ...]


class ChangeView(Protocol):
    @property
    def touched(self) -> frozenset[ModuleId]: ...


class ImpactView(Protocol):
    @property
    def impacted(self) -> frozenset[ModuleId]: ...


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


@dataclass(frozen=True)
class IncrementalState:
    reused_evaluations: int
    evaluated_evaluations: int
    full_rerun: bool
    registry_identity: _RegistryIdentity


@dataclass(frozen=True)
class IncrementalPolicyResult:
    result: PolicyRunResult
    state: IncrementalState


@dataclass(frozen=True)
class _Execution:
    result: PolicyRunResult
    reused: int
    evaluated: int


class PolicyEngine:
    def __init__(self, registry: RuleRegistry, scheduler: RuleScheduler | None = None) -> None:
        self._registry = registry
        self._scheduler = scheduler or RuleScheduler()

    def run(self, context: PolicyContext) -> PolicyRunResult:
        return self._execute(context, {}).result

    def run_tracked(self, context: PolicyContext) -> IncrementalPolicyResult:
        execution = self._execute(context, {})
        return IncrementalPolicyResult(
            execution.result,
            IncrementalState(
                0,
                execution.evaluated,
                True,
                self._registry_identity(),
            ),
        )

    def run_incremental(
        self,
        context: PolicyContext,
        prior_context: PolicyContext,
        prior_result: PolicyRunResult | IncrementalPolicyResult,
        changes: ChangeView,
        impact_graph: ImpactView,
    ) -> IncrementalPolicyResult:
        if not isinstance(prior_result, IncrementalPolicyResult):
            return self.run_tracked(context)
        previous = prior_result.result
        identity = self._registry_identity()
        if (
            prior_result.state.registry_identity != identity
            or previous.engine_issues
            or not self._safe_context(context, prior_context, changes)
        ):
            return self.run_tracked(context)
        old: dict[_EvaluationKey, RuleEvaluation] = {
            (evaluation.rule_id, evaluation.target): evaluation
            for evaluation in previous.evaluations
        }
        reuse: dict[_EvaluationKey, RuleEvaluation] = {}
        for rule_id, definition in self._registry.definitions.items():
            for key, evaluation in old.items():
                if key[0] != rule_id:
                    continue
                if not changes.touched:
                    reuse[key] = evaluation
                    continue
                module = evaluation.target.module_id
                if module is None:
                    continue
                if definition.change_impact is ChangeImpact.PROJECT:
                    continue
                invalidated = (
                    changes.touched
                    if definition.change_impact is ChangeImpact.SELF
                    else impact_graph.impacted
                )
                if module not in invalidated:
                    reuse[key] = evaluation
        execution = self._execute(context, reuse)
        return IncrementalPolicyResult(
            execution.result,
            IncrementalState(
                execution.reused,
                execution.evaluated,
                False,
                identity,
            ),
        )

    # Explicit alias for callers that name the operation after its evaluation
    # semantics rather than the ordinary ``run`` API.
    evaluate_incremental = run_incremental

    def _safe_context(
        self,
        context: PolicyContext,
        prior: PolicyContext,
        changes: ChangeView,
    ) -> bool:
        if (
            context.policy != prior.policy
            or context.catalog != prior.catalog
            or context.model.capabilities() != prior.model.capabilities()
            or self._project_complete(context) != self._project_complete(prior)
        ):
            return False
        current_modules = set(context.model.modules())
        prior_modules = set(prior.model.modules())
        if (current_modules ^ prior_modules).difference(changes.touched):
            return False
        for module_id in (current_modules & prior_modules).difference(changes.touched):
            if (
                context.classification.get(module_id) != prior.classification.get(module_id)
                or context.model.module(module_id).completeness
                != prior.model.module(module_id).completeness
            ):
                return False
        return True

    @staticmethod
    def _project_complete(context: PolicyContext) -> bool:
        return all(
            context.model.module(module_id).completeness.state is CompletenessState.COMPLETE
            for module_id in context.model.modules()
        )

    def _registry_identity(self) -> _RegistryIdentity:
        return tuple(
            (
                rule_id,
                definition.behavior_version,
                definition.target,
                definition.change_impact,
                definition.requirements,
                definition.applies_to_zones,
                definition.default_level,
                definition.implementation.__class__.__module__,
                definition.implementation.__class__.__qualname__,
            )
            for rule_id, definition in self._registry.definitions.items()
        )

    def _execute(
        self,
        context: PolicyContext,
        reuse: Mapping[_EvaluationKey, RuleEvaluation],
    ) -> _Execution:
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
                cached = reuse.get((rule_id, target))
                if cached is not None:
                    evaluations.append(cached)
                    continue
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
        result = PolicyRunResult(ordered, findings, tuple(issues), coverage)
        reused = sum((item.rule_id, item.target) in reuse for item in ordered)
        return _Execution(result, reused, len(ordered) - reused)

    def _missing_requirement(
        self,
        requirements: RuleRequirements,
        target: RuleTargetRef,
        context: PolicyContext,
        project_is_complete: bool,
    ) -> EvaluationReason | None:
        missing_capabilities = requirements.capabilities.difference(context.model.capabilities())
        if missing_capabilities:
            return EvaluationReason(
                "missing_capability",
                "규칙에 필요한 추가 분석 자료가 없습니다: "
                + ", ".join(sorted(missing_capabilities)),
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
    gaps = tuple(
        CoverageIssue(
            evaluation.rule_id,
            evaluation.target,
            gap,
            context.policy.setting(evaluation.rule_id).level,
        )
        for evaluation in evaluations
        for gap in evaluation.coverage_gaps
    )
    return CoverageReport(
        enabled_rules=enabled_rules,
        total_targets=len(evaluations),
        passed=verdicts.count(RuleVerdict.PASS),
        failed=verdicts.count(RuleVerdict.FAIL),
        not_applicable=verdicts.count(RuleVerdict.NOT_APPLICABLE),
        indeterminate=verdicts.count(RuleVerdict.INDETERMINATE),
        skipped=skipped,
        gaps=gaps,
    )
