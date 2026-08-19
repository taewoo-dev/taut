from __future__ import annotations

from dataclasses import dataclass

from taut.domain.ids import RuleId
from taut.domain.location import ProjectPath, SourceRange


@dataclass(frozen=True, order=True)
class InlineIgnore:
    path: ProjectPath
    line: int
    rule_id: RuleId
    location: SourceRange

    def __post_init__(self) -> None:
        if self.line < 0:
            raise ValueError("ignore line cannot be negative")

    @property
    def key(self) -> str:
        return f"{self.path.value}:{self.line + 1}:{self.rule_id.value}"
