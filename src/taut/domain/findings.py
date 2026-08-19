from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum

from taut.domain.frozen import FrozenMap
from taut.domain.ids import FactId, FindingFingerprint, ModuleId, RuleId, SymbolId
from taut.domain.location import SourceRange

type ScalarValue = str | int | float | bool | None
type EvidenceValue = ScalarValue | tuple[str, ...]


class FindingSource(StrEnum):
    STATIC = "static"
    RUNTIME = "runtime"


@dataclass(frozen=True, order=True)
class RelatedLocation:
    location: SourceRange
    message: str


@dataclass(frozen=True, order=True)
class EvidenceItem:
    key: str
    value: EvidenceValue

    def __post_init__(self) -> None:
        if not self.key.strip():
            raise ValueError("evidence key cannot be empty")


type FindingSubject = FactId | ModuleId | SymbolId


@dataclass(frozen=True)
class Finding:
    rule_id: RuleId
    rule_version: int
    subject: FindingSubject
    message_key: str
    arguments: FrozenMap[str, ScalarValue]
    primary_location: SourceRange
    related_locations: tuple[RelatedLocation, ...]
    evidence: tuple[EvidenceItem, ...]
    fingerprint: FindingFingerprint
    source: FindingSource = FindingSource.STATIC

    def __post_init__(self) -> None:
        if self.rule_version < 1:
            raise ValueError("rule version must be positive")
        if not self.message_key.strip():
            raise ValueError("message key cannot be empty")


def make_fingerprint(
    *,
    rule_id: RuleId,
    rule_version: int,
    module_id: ModuleId,
    enclosing_symbol: SymbolId | None,
    normalized_subject: str,
    evidence_key: str,
) -> FindingFingerprint:
    payload = json.dumps(
        {
            "rule_id": rule_id.value,
            "rule_version": rule_version,
            "module_id": module_id.value,
            "enclosing_symbol": enclosing_symbol.value if enclosing_symbol else None,
            "subject": normalized_subject,
            "evidence": evidence_key,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return FindingFingerprint(hashlib.sha256(payload.encode()).hexdigest())
