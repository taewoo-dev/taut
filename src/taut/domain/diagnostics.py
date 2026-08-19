from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from taut.domain.evaluations import RuleLevel
from taut.domain.findings import EvidenceItem, FindingSource, RelatedLocation
from taut.domain.ids import FindingFingerprint, RuleId
from taut.domain.location import SourceRange


class FindingDisposition(StrEnum):
    ACTIVE = "active"
    IGNORED = "ignored"


@dataclass(frozen=True)
class Diagnostic:
    rule_id: RuleId
    level: RuleLevel
    message: str
    primary_location: SourceRange
    related_locations: tuple[RelatedLocation, ...]
    evidence: tuple[EvidenceItem, ...]
    help: str | None
    fingerprint: FindingFingerprint
    disposition: FindingDisposition
    source: FindingSource

    def __post_init__(self) -> None:
        if not self.message.strip():
            raise ValueError("diagnostic message cannot be empty")
