from __future__ import annotations

from dataclasses import dataclass

from taut.domain.facts import (
    CompletenessState,
    ModuleFacts,
    ProjectIndex,
)
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, SnapshotId
from taut.domain.issues import EngineIssue


@dataclass(frozen=True, order=True)
class AnalysisInputDigest:
    value: str

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise ValueError("analysis input digest cannot be empty")


@dataclass(frozen=True, order=True)
class UnavailableCapability:
    name: str
    reason: str


@dataclass(frozen=True)
class AnalysisCoverage:
    requested_sources: int
    complete_modules: int
    partial_modules: int
    failed_modules: int
    unavailable_capabilities: tuple[UnavailableCapability, ...] = ()

    def __post_init__(self) -> None:
        values = (
            self.requested_sources,
            self.complete_modules,
            self.partial_modules,
            self.failed_modules,
        )
        if any(value < 0 for value in values):
            raise ValueError("analysis coverage counts cannot be negative")
        if self.requested_sources != sum(values[1:]):
            raise ValueError("requested source count must equal complete + partial + failed")


@dataclass(frozen=True)
class AnalysisSnapshot:
    id: SnapshotId
    inputs: AnalysisInputDigest
    modules: FrozenMap[ModuleId, ModuleFacts]
    project: ProjectIndex
    capabilities: FrozenMap[str, tuple[object, ...]]
    coverage: AnalysisCoverage
    issues: tuple[EngineIssue, ...]

    def __post_init__(self) -> None:
        if set(self.modules) != set(self.project.imports):
            raise ValueError("snapshot modules and project index modules must match")
        for module_id, facts in self.modules.items():
            if module_id != facts.module.id:
                raise ValueError("module map key must match ModuleFacts identity")
        states = tuple(facts.completeness.state for facts in self.modules.values())
        actual = (
            states.count(CompletenessState.COMPLETE),
            states.count(CompletenessState.PARTIAL),
            states.count(CompletenessState.FAILED),
        )
        expected = (
            self.coverage.complete_modules,
            self.coverage.partial_modules,
            self.coverage.failed_modules,
        )
        if actual != expected:
            raise ValueError("snapshot module completeness counts do not match coverage")
