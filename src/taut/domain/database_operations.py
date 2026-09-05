from __future__ import annotations

from dataclasses import dataclass

from taut.domain.facts import ResolutionState


@dataclass(frozen=True)
class DatabaseOperation:
    """Database behavior consumed by policies independently of provider fact types."""

    provider: str
    operation: str
    confidence: ResolutionState
    is_write: bool = False
