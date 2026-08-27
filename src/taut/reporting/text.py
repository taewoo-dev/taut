from __future__ import annotations

import unicodedata

from taut.domain.diagnostics import Diagnostic, FindingDisposition
from taut.domain.evaluations import RuleLevel
from taut.domain.location import ConfigLocation, SourceRange
from taut.domain.reports import RunReport

_RED = "\033[31m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_GREEN = "\033[32m"
_DIM = "\033[2m"
_RESET = "\033[0m"
DEFAULT_TEXT_WIDTH = 120
MINIMUM_TEXT_WIDTH = 60


def render_text(
    report: RunReport,
    *,
    show_inactive: bool = False,
    verbose: bool = False,
    color: bool = False,
    width: int = DEFAULT_TEXT_WIDTH,
) -> str:
    width = max(width, MINIMUM_TEXT_WIDTH)
    lines: list[str] = []
    for diagnostic in report.diagnostics:
        if not show_inactive and diagnostic.disposition is not FindingDisposition.ACTIVE:
            continue
        location = diagnostic.primary_location
        label, label_color = _diagnostic_label(diagnostic)
        lines.extend(
            _render_issue(
                prefix=(
                    f"{location.path.value}:{location.display_line}:{location.display_column}: "
                ),
                label=label,
                label_color=label_color,
                message=diagnostic.message,
                code=diagnostic.rule_id.value,
                color=color,
                width=width,
            )
        )
        if verbose:
            for related in diagnostic.related_locations:
                item = related.location
                lines.extend(
                    _wrap(
                        f"  관련: {item.path.value}:{item.display_line}:"
                        f"{item.display_column}: {related.message}",
                        width,
                    )
                )
            if diagnostic.help:
                lines.extend(_wrap(f"  도움: {diagnostic.help}", width))
    for issue in report.engine_issues:
        lines.extend(
            _render_issue(
                prefix=_issue_location(issue.location),
                label="error",
                label_color=_RED,
                message=issue.message,
                code=f"engine:{issue.code}",
                color=color,
                width=width,
            )
        )
        if verbose and issue.cause:
            lines.extend(_wrap(f"  원인: {issue.cause}", width))
    for assurance_issue in report.assurance.issues:
        lines.extend(
            _render_issue(
                prefix="",
                label="error",
                label_color=_RED,
                message=f"{assurance_issue.message} ({assurance_issue.subject})",
                code=f"assurance:{assurance_issue.code}",
                color=color,
                width=width,
            )
        )
        if verbose:
            lines.extend(_wrap(f"  도움: {assurance_issue.remediation}", width))
    for skipped in report.coverage.skipped:
        target = skipped.target
        subject = target.module_id or target.symbol_id or target.fact_id or "project"
        label = "error" if skipped.required_level is RuleLevel.ENFORCED else "warning"
        label_color = _RED if skipped.required_level is RuleLevel.ENFORCED else _YELLOW
        lines.extend(
            _render_issue(
                prefix="",
                label=label,
                label_color=label_color,
                message=f"판단 불가: {skipped.reason.message} ({subject})",
                code=skipped.rule_id.value,
                color=color,
                width=width,
            )
        )
    for gap in report.coverage.gaps:
        target = gap.target
        subject = target.module_id.value if target.module_id is not None else target.kind.value
        label = "error" if gap.required_level is RuleLevel.ENFORCED else "warning"
        label_color = _RED if gap.required_level is RuleLevel.ENFORCED else _YELLOW
        lines.extend(
            _render_issue(
                prefix="",
                label=label,
                label_color=label_color,
                message=f"분석 범위 부족: {gap.reason.message} ({subject})",
                code=gap.rule_id.value,
                color=color,
                width=width,
            )
        )

    active = tuple(
        item for item in report.diagnostics if item.disposition is FindingDisposition.ACTIVE
    )
    errors = sum(item.level is RuleLevel.ENFORCED for item in active)
    warnings = sum(item.level is RuleLevel.ADVISORY for item in active)
    summary = _summary(errors, warnings, len(report.engine_issues), report.coverage.indeterminate)
    summary_color = _RED if errors or report.engine_issues else _YELLOW if warnings else _GREEN
    lines.append(_paint(summary, summary_color, color))

    if not verbose:
        return "\n".join(lines)

    coverage = report.coverage
    lines.append(
        "상세 판정: "
        f"통과 {coverage.passed}, 위반 {coverage.failed}, 대상 아님 {coverage.not_applicable}, "
        f"판단 불가 {coverage.indeterminate}"
    )
    lines.append(
        f"ignore: 사용 {len(report.ignore_audit.used)}, 미사용 {len(report.ignore_audit.unused)}"
    )
    lines.append(
        "approval: "
        f"사용 {len(report.approval_audit.used)}, 미사용 {len(report.approval_audit.unused)}"
    )
    lines.append(
        "assurance: "
        f"분석 {report.assurance.analyzed_python_files}/"
        f"발견 {report.assurance.discovered_python_files}, "
        f"제외 {report.assurance.excluded_python_files}, "
        f"문제 {len(report.assurance.issues)}"
    )
    lines.append(f"판정 기준: {report.run.decision_digest}")
    reason = f" ({', '.join(report.exit_decision.reasons)})" if report.exit_decision.reasons else ""
    lines.append(f"종료 값: {report.exit_decision.code}{reason}")
    return "\n".join(lines)


def _diagnostic_label(diagnostic: Diagnostic) -> tuple[str, str]:
    if diagnostic.disposition is FindingDisposition.IGNORED:
        return "ignored", _DIM
    if diagnostic.level is RuleLevel.ENFORCED:
        return "error", _RED
    return "warning", _YELLOW


def _summary(errors: int, warnings: int, engine_issues: int, indeterminate: int) -> str:
    if not any((errors, warnings, engine_issues, indeterminate)):
        return "검사 완료: 문제 없음"
    parts = [f"오류 {errors:,}건", f"경고 {warnings:,}건"]
    if engine_issues:
        parts.append(f"검사 문제 {engine_issues:,}건")
    if indeterminate:
        parts.append(f"판단 불가 {indeterminate:,}건")
    return f"검사 완료: {', '.join(parts)}"


def _paint(value: str, style: str, enabled: bool) -> str:
    if not enabled:
        return value
    return f"{style}{value}{_RESET}"


def _render_issue(
    *,
    prefix: str,
    label: str,
    label_color: str,
    message: str,
    code: str,
    color: bool,
    width: int,
) -> tuple[str, ...]:
    label_token = f"{label}:"
    code_token = f"[{code}]"
    rendered = list(_wrap(f"{prefix}{label_token} {code_token} {message}", width))
    for index, line in enumerate(rendered):
        if label_token not in line:
            continue
        rendered[index] = line.replace(
            label_token,
            _paint(label_token, label_color, color),
            1,
        )
        break
    for index, line in enumerate(rendered):
        if code_token not in rendered[index]:
            continue
        rendered[index] = line.replace(
            code_token,
            _paint(code_token, _CYAN, color),
            1,
        )
        break
    return tuple(rendered)


def _wrap(value: str, width: int) -> tuple[str, ...]:
    stripped = value.strip()
    if not stripped:
        return ("",)
    initial_indent = value[: len(value) - len(value.lstrip())]
    words = stripped.split()
    current = f"{initial_indent}{words[0]}"
    lines: list[str] = []
    for word in words[1:]:
        candidate = f"{current} {word}"
        if _display_width(candidate) <= width:
            current = candidate
            continue
        lines.append(current)
        current = f"    {word}"
    lines.append(current)
    return tuple(lines)


def _display_width(value: str) -> int:
    width = 0
    for character in value:
        if unicodedata.combining(character):
            continue
        width += 2 if unicodedata.east_asian_width(character) in {"F", "W"} else 1
    return width


def _issue_location(location: SourceRange | ConfigLocation | None) -> str:
    if isinstance(location, SourceRange):
        return f"{location.path.value}:{location.display_line}:{location.display_column}: "
    if isinstance(location, ConfigLocation):
        line = f":{location.line + 1}" if location.line is not None else ""
        return f"{location.path.value}{line}: "
    return ""
