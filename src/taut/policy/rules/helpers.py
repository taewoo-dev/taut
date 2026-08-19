from __future__ import annotations

from taut.domain.findings import (
    EvidenceItem,
    Finding,
    FindingSubject,
    RelatedLocation,
    ScalarValue,
    make_fingerprint,
)
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, RuleId, SymbolId
from taut.domain.location import SourceRange


def build_finding(
    *,
    rule_id: RuleId,
    rule_version: int,
    module_id: ModuleId,
    enclosing_symbol: SymbolId | None,
    subject: FindingSubject,
    normalized_subject: str,
    message_key: str,
    arguments: tuple[tuple[str, ScalarValue], ...],
    location: SourceRange,
    evidence: tuple[EvidenceItem, ...],
    related_locations: tuple[RelatedLocation, ...] = (),
) -> Finding:
    evidence_key = "|".join(f"{item.key}={item.value}" for item in evidence)
    return Finding(
        rule_id=rule_id,
        rule_version=rule_version,
        subject=subject,
        message_key=message_key,
        arguments=FrozenMap(arguments),
        primary_location=location,
        related_locations=related_locations,
        evidence=evidence,
        fingerprint=make_fingerprint(
            rule_id=rule_id,
            rule_version=rule_version,
            module_id=module_id,
            enclosing_symbol=enclosing_symbol,
            normalized_subject=normalized_subject,
            evidence_key=evidence_key,
        ),
    )
