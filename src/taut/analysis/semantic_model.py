from __future__ import annotations

from typing import Protocol

from taut.domain.facts import (
    CallFact,
    ImportCycle,
    ModuleFacts,
    SymbolRef,
    UnresolvedImport,
)
from taut.domain.ids import FactId, ModuleId, SnapshotId
from taut.domain.snapshot import AnalysisSnapshot


class SemanticModel(Protocol):
    @property
    def snapshot_id(self) -> SnapshotId: ...

    def modules(self) -> tuple[ModuleId, ...]: ...

    def module(self, module_id: ModuleId) -> ModuleFacts: ...

    def imports_of(self, module_id: ModuleId) -> tuple[ModuleId, ...]: ...

    def imported_by(self, module_id: ModuleId) -> tuple[ModuleId, ...]: ...

    def import_cycles(self) -> tuple[ImportCycle, ...]: ...

    def unresolved_imports(self) -> tuple[UnresolvedImport, ...]: ...

    def calls_in(self, module_id: ModuleId) -> tuple[CallFact, ...]: ...

    def call(self, fact_id: FactId) -> CallFact: ...

    def resolve(self, ref: SymbolRef) -> SymbolRef: ...


class SnapshotSemanticModel:
    def __init__(self, snapshot: AnalysisSnapshot) -> None:
        self._snapshot = snapshot
        self._calls = {
            call.id: call for module in snapshot.modules.values() for call in module.calls
        }

    @property
    def snapshot_id(self) -> SnapshotId:
        return self._snapshot.id

    def modules(self) -> tuple[ModuleId, ...]:
        return tuple(self._snapshot.modules)

    def module(self, module_id: ModuleId) -> ModuleFacts:
        return self._snapshot.modules[module_id]

    def imports_of(self, module_id: ModuleId) -> tuple[ModuleId, ...]:
        return self._snapshot.project.imports[module_id]

    def imported_by(self, module_id: ModuleId) -> tuple[ModuleId, ...]:
        return self._snapshot.project.imported_by[module_id]

    def import_cycles(self) -> tuple[ImportCycle, ...]:
        return self._snapshot.project.cycles

    def unresolved_imports(self) -> tuple[UnresolvedImport, ...]:
        return self._snapshot.project.unresolved_imports

    def calls_in(self, module_id: ModuleId) -> tuple[CallFact, ...]:
        return self._snapshot.modules[module_id].calls

    def call(self, fact_id: FactId) -> CallFact:
        return self._calls[fact_id]

    def resolve(self, ref: SymbolRef) -> SymbolRef:
        return ref
