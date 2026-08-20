from __future__ import annotations

from dataclasses import dataclass, field

from taut.domain.facts import (
    CompletenessState,
    ModuleFacts,
    ProjectIndex,
)
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, SnapshotId
from taut.domain.issues import EngineIssue
from taut.domain.provenance import Provenance
from taut.domain.relations import ProjectRelations


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


@dataclass(frozen=True, order=True)
class ResolutionCoverage:
    resolved: int = 0
    conditional: int = 0
    ambiguous: int = 0
    unresolved: int = 0
    dynamic: int = 0

    def __post_init__(self) -> None:
        if any(value < 0 for value in self.values()):
            raise ValueError("resolution coverage counts cannot be negative")

    def values(self) -> tuple[int, int, int, int, int]:
        return self.resolved, self.conditional, self.ambiguous, self.unresolved, self.dynamic

    @property
    def total(self) -> int:
        return sum(self.values())


@dataclass(frozen=True)
class AnalysisCoverage:
    requested_sources: int
    complete_modules: int
    partial_modules: int
    failed_modules: int
    unavailable_capabilities: tuple[UnavailableCapability, ...] = ()
    capability_provenance: tuple[tuple[str, Provenance], ...] = ()
    calls: ResolutionCoverage = ResolutionCoverage()
    references: ResolutionCoverage = ResolutionCoverage()
    resolved_imports: int = 0
    unresolved_imports: int = 0

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
        if self.resolved_imports < 0 or self.unresolved_imports < 0:
            raise ValueError("import coverage counts cannot be negative")


@dataclass(frozen=True)
class AnalysisSnapshot:
    id: SnapshotId
    inputs: AnalysisInputDigest
    modules: FrozenMap[ModuleId, ModuleFacts]
    project: ProjectIndex
    relations: ProjectRelations
    capabilities: FrozenMap[str, tuple[object, ...]]
    coverage: AnalysisCoverage
    issues: tuple[EngineIssue, ...]
    capability_provenance: FrozenMap[str, Provenance] = field(
        default_factory=lambda: FrozenMap[str, Provenance]()
    )

    def __post_init__(self) -> None:
        if set(self.modules) != set(self.project.imports):
            raise ValueError("snapshot modules and project index modules must match")
        if self.relations.import_edges != self.project.import_edges:
            raise ValueError("snapshot relations and project import edges must match")
        if not set(self.capability_provenance).issubset(self.capabilities):
            raise ValueError("capability provenance must refer to an available capability")
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
