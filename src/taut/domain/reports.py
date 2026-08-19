from __future__ import annotations

from dataclasses import dataclass

from taut.domain.diagnostics import Diagnostic
from taut.domain.evaluations import EvaluationReason, RuleLevel, RuleTargetRef
from taut.domain.ids import RuleId, SnapshotId
from taut.domain.issues import EngineIssue


@dataclass(frozen=True, order=True)
class CoverageIssue:
    rule_id: RuleId
    target: RuleTargetRef
    reason: EvaluationReason
    required_level: RuleLevel


@dataclass(frozen=True)
class CoverageReport:
    enabled_rules: int
    total_targets: int
    passed: int
    failed: int
    not_applicable: int
    indeterminate: int
    skipped: tuple[CoverageIssue, ...]

    def __post_init__(self) -> None:
        counts = (
            self.enabled_rules,
            self.total_targets,
            self.passed,
            self.failed,
            self.not_applicable,
            self.indeterminate,
        )
        if any(value < 0 for value in counts):
            raise ValueError("coverage counts cannot be negative")
        if self.total_targets != sum(counts[2:]):
            raise ValueError("target count must equal all four verdict counts")
        if len(self.skipped) != self.indeterminate:
            raise ValueError("every indeterminate verdict must have one coverage issue")


@dataclass(frozen=True, order=True)
class IgnoreAudit:
    used: tuple[str, ...] = ()
    unused: tuple[str, ...] = ()


@dataclass(frozen=True, order=True)
class RunMetadata:
    engine_version: str
    report_schema_version: int
    snapshot_id: SnapshotId
    decision_digest: str

    def __post_init__(self) -> None:
        if self.report_schema_version < 1:
            raise ValueError("report schema version must be positive")
        if not self.engine_version.strip() or not self.decision_digest.strip():
            raise ValueError("run metadata values cannot be empty")


@dataclass(frozen=True, order=True)
class ExitDecision:
    code: int
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.code not in (0, 1, 2):
            raise ValueError("exit code must be 0, 1, or 2")
        if self.code != 0 and not self.reasons:
            raise ValueError("non-zero exit decision requires a reason")


@dataclass(frozen=True)
class RunReport:
    run: RunMetadata
    diagnostics: tuple[Diagnostic, ...]
    engine_issues: tuple[EngineIssue, ...]
    coverage: CoverageReport
    ignore_audit: IgnoreAudit
    exit_decision: ExitDecision
