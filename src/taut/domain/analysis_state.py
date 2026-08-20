from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from taut.domain.frozen import FrozenMap


class AnalysisStage(StrEnum):
    DISCOVERED = "discovered"
    PARSED = "parsed"
    INDEXED = "indexed"
    RESOLVED = "resolved"
    FACTS_READY = "facts_ready"
    FAILED = "failed"


class FactKind(StrEnum):
    IMPORT = "import"
    DEFINITION = "definition"
    REFERENCE = "reference"
    CALL = "call"
    DECORATOR = "decorator"
    FUNCTION = "function"
    CLASS = "class"
    FIELD = "field"


class CompletenessState(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True, order=True)
class IncompleteReason:
    code: str
    message: str


@dataclass(frozen=True)
class ModuleCompleteness:
    state: CompletenessState
    stage: AnalysisStage
    available_facts: frozenset[FactKind]
    unavailable_facts: FrozenMap[FactKind, IncompleteReason]

    def __post_init__(self) -> None:
        overlap = self.available_facts.intersection(self.unavailable_facts)
        if overlap:
            raise ValueError(f"fact kinds cannot be both available and unavailable: {overlap}")
        if self.state is CompletenessState.COMPLETE and (
            self.stage is not AnalysisStage.FACTS_READY or self.unavailable_facts
        ):
            raise ValueError("complete module must be facts_ready with no unavailable facts")
        if self.state is CompletenessState.FAILED and self.stage is not AnalysisStage.FAILED:
            raise ValueError("failed module must be in failed stage")
