from __future__ import annotations

from taut.domain.diagnostics import Diagnostic, FindingDisposition
from taut.domain.evaluations import RuleLevel
from taut.domain.issues import EngineIssue
from taut.domain.reports import (
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
) -> RunReport:
    return RunReport(
        run=RunMetadata(engine_version, 2, snapshot.id, decision_digest),
        diagnostics=diagnostics,
        engine_issues=engine_issues,
        coverage=coverage,
        ignore_audit=ignore_audit,
        exit_decision=decide_exit(diagnostics, engine_issues, coverage),
    )


def decide_exit(
    diagnostics: tuple[Diagnostic, ...],
    engine_issues: tuple[EngineIssue, ...],
    coverage: CoverageReport,
) -> ExitDecision:
    trust_failures: list[str] = []
    if engine_issues:
        trust_failures.append("설정 또는 분석 문제")
    if any(issue.required_level is RuleLevel.ENFORCED for issue in coverage.skipped):
        trust_failures.append("강제 규칙 판단 불가")
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
