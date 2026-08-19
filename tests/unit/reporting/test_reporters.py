from __future__ import annotations

import json
from typing import cast

from tests.utils.builders import analyze, make_context, make_source

from taut import __version__
from taut.domain.evaluations import RuleLevel
from taut.domain.frozen import FrozenMap
from taut.domain.ids import RuleId
from taut.domain.reports import RunReport
from taut.finding_processing.finding_processor import FindingProcessor
from taut.finding_processing.report_builder import build_run_report
from taut.policy.engine import PolicyEngine
from taut.policy.rules import builtin_rule_registry
from taut.reporting.json import render_json
from taut.reporting.text import render_text


def _report(*, level: RuleLevel = RuleLevel.ENFORCED) -> RunReport:
    snapshot = analyze(
        make_source("app/service.py", "from datetime import datetime\nvalue = datetime.now()")
    )
    context = make_context(
        snapshot,
        roles={"service": ("app/**",)},
        levels={"TIME001": level},
    )
    registry = builtin_rule_registry()
    policy_result = PolicyEngine(registry).run(context)
    processing = FindingProcessor().process(
        findings=policy_result.findings,
        policy=context.policy,
        help_by_rule=FrozenMap(((RuleId("TIME001"), "use clock"),)),
        ignores=(),
    )
    return build_run_report(
        snapshot=snapshot,
        engine_version=__version__,
        decision_digest="a" * 64,
        diagnostics=processing.diagnostics,
        engine_issues=(),
        coverage=policy_result.coverage,
        ignore_audit=processing.ignore_audit,
    )


def test_text_and_json_report_same_rule_and_location() -> None:
    report = _report()
    text = render_text(report)
    payload = cast(dict[str, object], json.loads(render_json(report)))
    diagnostics = cast(list[dict[str, object]], payload["diagnostics"])
    location = cast(dict[str, object], diagnostics[0]["location"])

    assert "app/service.py:2" in text
    assert "TIME001" in text
    assert diagnostics[0]["rule_id"] == "TIME001"
    assert location["path"] == "app/service.py"
    assert payload["decision_digest"] == "a" * 64


def test_text_output_is_compact_by_default_and_verbose_on_request() -> None:
    report = _report()

    compact = render_text(report)
    verbose = render_text(report, verbose=True)

    assert "error:" in compact
    assert "[TIME001]" in compact
    assert "검사 완료: 오류 1건, 경고 0건" in compact
    assert "도움:" not in compact
    assert "판정 기준:" not in compact
    assert "도움: use clock" in verbose
    assert "판정 기준:" in verbose


def test_text_output_uses_warning_for_advisory_findings() -> None:
    text = render_text(_report(level=RuleLevel.ADVISORY))

    assert "warning:" in text
    assert "검사 완료: 오류 0건, 경고 1건" in text


def test_text_output_can_add_terminal_colors() -> None:
    text = render_text(_report(), color=True)

    assert "\033[31merror:\033[0m" in text
    assert "\033[36m[TIME001]\033[0m" in text


def test_text_output_wraps_long_diagnostics_with_indentation() -> None:
    text = render_text(_report(), width=60)
    diagnostic_lines = text.splitlines()[:-1]

    assert len(diagnostic_lines) > 1
    assert diagnostic_lines[0] == ("app/service.py:2:9: error: [TIME001] 승인되지 않은 시간 조회")
    assert diagnostic_lines[1].startswith("    datetime.datetime.now")
    assert all(len(line) <= 60 for line in diagnostic_lines)


def test_json_output_is_deterministic() -> None:
    report = _report()

    assert render_json(report) == render_json(report)
