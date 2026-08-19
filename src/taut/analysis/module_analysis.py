from __future__ import annotations

from dataclasses import dataclass

from taut.domain.facts import AnalysisStage

_NEXT_STAGE = {
    AnalysisStage.DISCOVERED: AnalysisStage.PARSED,
    AnalysisStage.PARSED: AnalysisStage.INDEXED,
    AnalysisStage.INDEXED: AnalysisStage.RESOLVED,
    AnalysisStage.RESOLVED: AnalysisStage.FACTS_READY,
}


@dataclass
class ModuleAnalysis:
    """Mutable analysis lifecycle. This value never leaves the analyzer."""

    stage: AnalysisStage = AnalysisStage.DISCOVERED

    def advance(self, stage: AnalysisStage) -> None:
        if self.stage is AnalysisStage.FAILED:
            raise ValueError("failed analysis cannot advance")
        if _NEXT_STAGE.get(self.stage) is not stage:
            raise ValueError(f"cannot move analysis from {self.stage.value} to {stage.value}")
        self.stage = stage

    def fail(self) -> None:
        if self.stage is AnalysisStage.FACTS_READY:
            raise ValueError("completed analysis cannot be marked failed")
        self.stage = AnalysisStage.FAILED
