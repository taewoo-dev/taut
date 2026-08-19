from __future__ import annotations

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
from taut.domain.facts import AnalysisStage
from taut.domain.findings import Finding
from taut.domain.ids import RuleId
from taut.policy.context import PolicyContext


@dataclass(frozen=True)
class RuleRequirements:
    capabilities: frozenset[str]
    minimum_stage: AnalysisStage
    needs_resolved_symbols: bool
    needs_complete_project: bool


class Rule(Protocol):
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation: ...


@dataclass(frozen=True)
class RuleDefinition:
    id: RuleId
    behavior_version: int
    title: str
    help: str
    target: RuleTarget
    requirements: RuleRequirements
    change_impact: ChangeImpact
    implementation: Rule
    compliant_fixtures: tuple[str, ...]
    violation_fixtures: tuple[str, ...]
    applies_to_zones: frozenset[Zone] = frozenset({Zone("prod")})
    default_level: RuleLevel = RuleLevel.ENFORCED

    def __post_init__(self) -> None:
        if self.behavior_version < 1:
            raise ValueError("rule behavior version must be positive")
        if not self.title.strip() or not self.help.strip():
            raise ValueError("rule title and help cannot be empty")
        if not self.compliant_fixtures or not self.violation_fixtures:
            raise ValueError("rule definition requires compliant and violation fixtures")
        if not self.applies_to_zones:
            raise ValueError("rule definition requires at least one applicable zone")


@dataclass(frozen=True)
class RuleEvaluation:
    rule_id: RuleId
    target: RuleTargetRef
    verdict: RuleVerdict
    findings: tuple[Finding, ...]
    reason: EvaluationReason | None = None

    def __post_init__(self) -> None:
        if self.verdict is RuleVerdict.FAIL and not self.findings:
            raise ValueError("failed evaluation requires at least one finding")
        if self.verdict is not RuleVerdict.FAIL and self.findings:
            raise ValueError("only failed evaluation can contain findings")
        if self.verdict is RuleVerdict.INDETERMINATE and self.reason is None:
            raise ValueError("indeterminate evaluation requires a reason")
        if self.verdict is not RuleVerdict.INDETERMINATE and self.reason is not None:
            raise ValueError("only indeterminate evaluation can contain a reason")
