from __future__ import annotations

from dataclasses import replace

from tests.utils.builders import analyze, make_context, make_source

from taut.domain.diagnostics import Diagnostic, FindingDisposition
from taut.domain.evaluations import RuleLevel
from taut.domain.issues import EngineIssue, EngineIssueKind
from taut.finding_processing.report_builder import decide_exit
from taut.policy.context import PolicyContext
from taut.policy.engine import PolicyEngine, PolicyRunResult
from taut.policy.rules import builtin_rule_registry


def _violating_run() -> tuple[PolicyRunResult, PolicyContext]:
    snapshot = analyze(
        make_source("app/service.py", "from datetime import datetime\nvalue = datetime.now()")
    )
    context = make_context(
        snapshot,
        roles={"service": ("app/**",)},
        levels={"TIME001": RuleLevel.ENFORCED},
    )
    return PolicyEngine(builtin_rule_registry()).run(context), context


def test_exit_decision_prioritizes_trust_failure_over_violation() -> None:
    result, _context = _violating_run()
    issue = EngineIssue(
        "BROKEN",
        EngineIssueKind.ANALYSIS_FAILURE,
        "analysis failed",
        None,
    )

    assert decide_exit((), (issue,), result.coverage).code == 2


def test_active_enforced_diagnostic_blocks_but_ignored_does_not() -> None:
    result, context = _violating_run()
    finding = result.findings[0]
    diagnostic = Diagnostic(
        finding.rule_id,
        context.policy.setting(finding.rule_id).level,
        "message",
        finding.primary_location,
        (),
        (),
        None,
        finding.fingerprint,
        FindingDisposition.ACTIVE,
        finding.source,
    )

    active = decide_exit((diagnostic,), (), result.coverage)
    ignored = decide_exit(
        (replace(diagnostic, disposition=FindingDisposition.IGNORED),),
        (),
        result.coverage,
    )

    assert active.code == 1
    assert ignored.code == 0
