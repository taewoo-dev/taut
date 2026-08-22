from __future__ import annotations

from dataclasses import replace

from tests.utils.builders import analyze, make_context, make_source

from taut.configuration.effective_policy import PolicyApproval
from taut.domain.diagnostics import FindingDisposition
from taut.domain.evaluations import RuleLevel
from taut.domain.frozen import FrozenMap
from taut.domain.ids import RuleId, SymbolId
from taut.domain.ignores import InlineIgnore
from taut.domain.location import ProjectPath, SourceRange
from taut.finding_processing.finding_processor import FindingProcessor
from taut.policy.context import PolicyContext
from taut.policy.engine import PolicyEngine, PolicyRunResult
from taut.policy.rules import builtin_rule_registry


def _time_result() -> tuple[PolicyContext, PolicyRunResult]:
    snapshot = analyze(
        make_source("app/service.py", "from datetime import datetime\nvalue = datetime.now()")
    )
    context = make_context(
        snapshot,
        roles={"service": ("app/**",)},
        levels={"TIME001": RuleLevel.ENFORCED, "IGNORE001": RuleLevel.ENFORCED},
    )
    return context, PolicyEngine(builtin_rule_registry()).run(context)


def _ignore(rule_id: str = "TIME001", line: int = 1) -> InlineIgnore:
    path = ProjectPath("app/service.py")
    return InlineIgnore(path, line, RuleId(rule_id), SourceRange(path, line, 23, line, 55))


def test_exact_inline_ignore_hides_only_matching_finding() -> None:
    context, policy_result = _time_result()
    finding = policy_result.findings[0]
    processor = FindingProcessor()
    help_by_rule: FrozenMap[RuleId, str] = FrozenMap(((RuleId("TIME001"), "use clock"),))

    active = processor.process(
        findings=(finding,), policy=context.policy, help_by_rule=help_by_rule, ignores=()
    )
    ignored = processor.process(
        findings=(finding,),
        policy=context.policy,
        help_by_rule=help_by_rule,
        ignores=(_ignore(),),
    )

    assert active.diagnostics[0].disposition is FindingDisposition.ACTIVE
    assert ignored.diagnostics[0].disposition is FindingDisposition.IGNORED
    assert ignored.ignore_audit.used == ("app/service.py:2:TIME001",)


def test_unused_inline_ignore_becomes_ignore001_violation() -> None:
    context, _policy_result = _time_result()

    result = FindingProcessor().process(
        findings=(),
        policy=context.policy,
        help_by_rule=FrozenMap(((RuleId("IGNORE001"), "remove it"),)),
        ignores=(_ignore(),),
    )

    assert result.diagnostics[0].rule_id == RuleId("IGNORE001")
    assert result.diagnostics[0].disposition is FindingDisposition.ACTIVE
    assert result.ignore_audit.unused == ("app/service.py:2:TIME001",)


def test_ignore_for_other_rule_does_not_hide_finding() -> None:
    context, policy_result = _time_result()

    result = FindingProcessor().process(
        findings=(policy_result.findings[0],),
        policy=context.policy,
        help_by_rule=FrozenMap(),
        ignores=(_ignore("ASYNC001"),),
    )

    assert result.diagnostics[0].rule_id == RuleId("TIME001")
    assert result.diagnostics[0].disposition is FindingDisposition.ACTIVE
    assert result.diagnostics[1].rule_id == RuleId("IGNORE001")


def test_symbol_target_approval_records_reason_and_audit_key() -> None:
    context, policy_result = _time_result()
    finding = policy_result.findings[0]
    target = str(finding.arguments["symbol"])
    approval = PolicyApproval(
        RuleId("TIME001"),
        SymbolId("app.service"),
        "legacy boundary wraps the clock at runtime",
        target=target,
        kind="allow",
    )
    policy = replace(context.policy, approvals=(approval,))

    result = FindingProcessor().process(
        findings=(finding,),
        policy=policy,
        help_by_rule=FrozenMap(),
        ignores=(),
        classifications=context.classification,
    )

    assert result.diagnostics[0].disposition is FindingDisposition.IGNORED
    assert result.ignore_audit.used == ()
    assert result.approval_audit.used == (approval.key,)
    assert ("approval_reason", approval.reason) in {
        (item.key, item.value) for item in result.diagnostics[0].evidence
    }


def test_approval_does_not_match_another_target() -> None:
    context, policy_result = _time_result()
    approval = PolicyApproval(
        RuleId("TIME001"),
        SymbolId("app.service"),
        "only monotonic is approved",
        target="time.monotonic",
    )
    policy = replace(context.policy, approvals=(approval,))

    result = FindingProcessor().process(
        findings=(policy_result.findings[0],),
        policy=policy,
        help_by_rule=FrozenMap(),
        ignores=(),
        classifications=context.classification,
    )

    assert result.diagnostics[0].disposition is FindingDisposition.ACTIVE
    assert result.ignore_audit.unused == ()
    assert result.approval_audit.unused == (approval.key,)
