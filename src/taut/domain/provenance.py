from __future__ import annotations

from dataclasses import dataclass

from taut.domain.location import SourceRange


@dataclass(frozen=True, order=True)
class Provenance:
    provider: str
    provider_version: str
    source_hash: str
    location: SourceRange | None

    def __post_init__(self) -> None:
        if not self.provider.strip():
            raise ValueError("provider cannot be empty")
        if not self.provider_version.strip():
            raise ValueError("provider version cannot be empty")
        if not self.source_hash.strip():
            raise ValueError("source hash cannot be empty")
