from __future__ import annotations

import io
import re
import tokenize
from dataclasses import dataclass

from taut.analysis.contracts import SourceInput
from taut.domain.ids import RuleId
from taut.domain.ignores import InlineIgnore
from taut.domain.issues import EngineIssue, EngineIssueKind
from taut.domain.location import SourceRange

_IGNORE_MARKER = "taut: ignore"
_IGNORE_PATTERN = re.compile(r"^#\s*taut:\s*ignore\[([A-Z][A-Z0-9]*\d{3})\]\s*$")


@dataclass(frozen=True)
class InlineIgnoreResult:
    directives: tuple[InlineIgnore, ...]
    issues: tuple[EngineIssue, ...]


def load_inline_ignores(
    sources: tuple[SourceInput, ...],
    known_rules: frozenset[RuleId],
) -> InlineIgnoreResult:
    directives: list[InlineIgnore] = []
    issues: list[EngineIssue] = []
    for source in sources:
        if _IGNORE_MARKER not in source.content:
            continue
        try:
            tokens = tokenize.generate_tokens(io.StringIO(source.content).readline)
            comments = tuple(token for token in tokens if token.type == tokenize.COMMENT)
        except (IndentationError, tokenize.TokenError):
            # The language adapter reports the parse failure with the source location.
            continue
        for comment in comments:
            if _IGNORE_MARKER not in comment.string:
                continue
            line = comment.start[0] - 1
            location = SourceRange(
                source.path,
                line,
                comment.start[1],
                comment.end[0] - 1,
                comment.end[1],
            )
            match = _IGNORE_PATTERN.fullmatch(comment.string)
            if match is None:
                issues.append(
                    EngineIssue(
                        code="INVALID_INLINE_IGNORE",
                        kind=EngineIssueKind.INVALID_CONFIGURATION,
                        message=("ignore 주석은 '# taut: ignore[RULE001]' 형식이어야 합니다."),
                        location=location,
                    )
                )
                continue
            rule_id = RuleId(match.group(1))
            if rule_id not in known_rules or rule_id == RuleId("IGNORE001"):
                issues.append(
                    EngineIssue(
                        code="UNKNOWN_INLINE_IGNORE_RULE",
                        kind=EngineIssueKind.INVALID_CONFIGURATION,
                        message=f"ignore 주석의 규칙 번호를 확인할 수 없습니다: {rule_id.value}",
                        location=location,
                    )
                )
                continue
            directives.append(InlineIgnore(source.path, line, rule_id, location))
    ordered = tuple(sorted(directives, key=lambda item: (item.path.value, item.line, item.rule_id)))
    return InlineIgnoreResult(
        ordered,
        tuple(sorted(issues, key=lambda item: (_issue_path(item), item.code))),
    )


def _issue_path(issue: EngineIssue) -> str:
    return issue.location.path.value if isinstance(issue.location, SourceRange) else ""
