from __future__ import annotations

from typing import Protocol

from taut.domain.facts import (
    CallFact,
    ImportCycle,
    ImportEdge,
    ModuleFacts,
    SymbolRef,
    UnresolvedImport,
)
from taut.domain.ids import FactId, ModuleId, SnapshotId, SymbolId
from taut.domain.relations import Binding, UseEdge
from taut.domain.snapshot import AnalysisSnapshot


class SemanticModel(Protocol):
    @property
    def snapshot_id(self) -> SnapshotId: ...

    def modules(self) -> tuple[ModuleId, ...]: ...

    def module(self, module_id: ModuleId) -> ModuleFacts: ...

    def imports_of(self, module_id: ModuleId) -> tuple[ModuleId, ...]: ...

    def import_edges_of(self, module_id: ModuleId) -> tuple[ImportEdge, ...]: ...

    def imported_by(self, module_id: ModuleId) -> tuple[ModuleId, ...]: ...

    def import_cycles(self) -> tuple[ImportCycle, ...]: ...

    def unresolved_imports(self) -> tuple[UnresolvedImport, ...]: ...

    def calls_in(self, module_id: ModuleId) -> tuple[CallFact, ...]: ...

    def call(self, fact_id: FactId) -> CallFact: ...

    def resolve(self, ref: SymbolRef) -> SymbolRef: ...

    def canonical_symbol(self, symbol: SymbolId) -> SymbolId: ...

    def capabilities(self) -> frozenset[str]: ...

    def capability_values(self, capability: str) -> tuple[object, ...]: ...

    def bindings(self, module_id: ModuleId | None = None) -> tuple[Binding, ...]: ...

    def uses(self, module_id: ModuleId | None = None) -> tuple[UseEdge, ...]: ...


class SnapshotSemanticModel:
    def __init__(self, snapshot: AnalysisSnapshot) -> None:
        self._snapshot = snapshot
        self._calls = {
            call.id: call for module in snapshot.modules.values() for call in module.calls
        }
        import_edges_by_module: dict[ModuleId, list[ImportEdge]] = {}
        for edge in snapshot.project.import_edges:
            import_edges_by_module.setdefault(edge.importer, []).append(edge)
        self._import_edges_by_module = {
            module_id: tuple(edges) for module_id, edges in import_edges_by_module.items()
        }
        self._bindings_by_module = snapshot.relations.bindings_by_module
        self._uses_by_module = snapshot.relations.use_edges_by_module
        self._canonical_by_value = {
            alias.value: canonical.value
            for alias, canonical in snapshot.project.canonical_symbols.items()
        }
        self._canonical_cache: dict[SymbolId, SymbolId] = {}

    @property
    def snapshot_id(self) -> SnapshotId:
        return self._snapshot.id

    def modules(self) -> tuple[ModuleId, ...]:
        return tuple(self._snapshot.modules)

    def module(self, module_id: ModuleId) -> ModuleFacts:
        return self._snapshot.modules[module_id]

    def imports_of(self, module_id: ModuleId) -> tuple[ModuleId, ...]:
        return self._snapshot.project.imports[module_id]

    def import_edges_of(self, module_id: ModuleId) -> tuple[ImportEdge, ...]:
        return self._import_edges_by_module.get(module_id, ())

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

    def canonical_symbol(self, symbol: SymbolId) -> SymbolId:
        cached = self._canonical_cache.get(symbol)
        if cached is not None:
            return cached
        prefix = symbol.value
        while prefix:
            canonical = self._canonical_by_value.get(prefix)
            if canonical is not None:
                suffix = symbol.value[len(prefix) :]
                result = SymbolId(f"{canonical}{suffix}")
                self._canonical_cache[symbol] = result
                return result
            prefix = prefix.rpartition(".")[0]
        self._canonical_cache[symbol] = symbol
        return symbol

    def capabilities(self) -> frozenset[str]:
        return frozenset(self._snapshot.capabilities)

    def capability_values(self, capability: str) -> tuple[object, ...]:
        return self._snapshot.capabilities.get(capability, ())

    def bindings(self, module_id: ModuleId | None = None) -> tuple[Binding, ...]:
        if module_id is None:
            return self._snapshot.relations.bindings
        return tuple(self._bindings_by_module.get(module_id, ()))

    def uses(self, module_id: ModuleId | None = None) -> tuple[UseEdge, ...]:
        if module_id is None:
            return self._snapshot.relations.use_edges
        return tuple(self._uses_by_module.get(module_id, ()))
