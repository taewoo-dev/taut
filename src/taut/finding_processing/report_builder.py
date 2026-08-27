from __future__ import annotations

from taut.domain.assurance import AssuranceReport
from taut.domain.diagnostics import Diagnostic, FindingDisposition
from taut.domain.evaluations import RuleLevel
from taut.domain.issues import EngineIssue
from taut.domain.reports import (
    ApprovalAudit,
    CoverageReport,
    ExitDecision,
    IgnoreAudit,
    RunMetadata,
    RunReport,
)
from taut.domain.snapshot import AnalysisSnapshot


def build_run_report(
    *,
    snapshot: AnalysisSnapshot,
    engine_version: str,
    decision_digest: str,
    diagnostics: tuple[Diagnostic, ...],
    engine_issues: tuple[EngineIssue, ...],
    coverage: CoverageReport,
    ignore_audit: IgnoreAudit,
    approval_audit: ApprovalAudit,
    assurance: AssuranceReport | None = None,
    enforce_assurance: bool = False,
) -> RunReport:
    assurance = assurance or AssuranceReport()
    return RunReport(
        run=RunMetadata(engine_version, 4, snapshot.id, decision_digest),
        diagnostics=diagnostics,
        engine_issues=engine_issues,
        coverage=coverage,
        analysis_coverage=snapshot.coverage,
        ignore_audit=ignore_audit,
        approval_audit=approval_audit,
        exit_decision=decide_exit(
            diagnostics,
            engine_issues,
            coverage,
            assurance if enforce_assurance else AssuranceReport(),
        ),
        assurance=assurance,
    )


def decide_exit(
    diagnostics: tuple[Diagnostic, ...],
    engine_issues: tuple[EngineIssue, ...],
    coverage: CoverageReport,
    assurance: AssuranceReport | None = None,
) -> ExitDecision:
    assurance = assurance or AssuranceReport()
    trust_failures: list[str] = []
    if engine_issues:
        trust_failures.append("설정 또는 분석 문제")
    if any(
        issue.required_level is RuleLevel.ENFORCED for issue in (*coverage.skipped, *coverage.gaps)
    ):
        trust_failures.append("강제 규칙 판단 불가")
    if assurance.issues:
        trust_failures.append("strict assurance 미완료")
    if trust_failures:
        return ExitDecision(2, tuple(trust_failures))
    blocking = any(
        diagnostic.disposition is FindingDisposition.ACTIVE
        and diagnostic.level is RuleLevel.ENFORCED
        for diagnostic in diagnostics
    )
    if blocking:
        return ExitDecision(1, ("강제 규칙 위반",))
    return ExitDecision(0, ())
