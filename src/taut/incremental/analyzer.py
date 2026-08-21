from __future__ import annotations

from taut.analysis.contracts import (
    AnalysisRequest,
    LanguageAdapter,
    ModuleAnalysisResult,
    SourceInput,
)
from taut.analysis.project_analyzer import ProjectAnalyzer
from taut.domain.ids import ModuleId
from taut.domain.snapshot import AnalysisSnapshot
from taut.incremental.changes import ChangeSet, ImpactGraph


class IncrementalProjectAnalyzer:
    def __init__(self, adapter: LanguageAdapter) -> None:
        self._adapter = adapter
        self._results: dict[ModuleId, ModuleAnalysisResult] = {}
        self._sources: tuple[SourceInput, ...] = ()
        self._request_identity: tuple[object, ...] | None = None
        self._snapshot: AnalysisSnapshot | None = None
        self.reparsed_modules = 0
        self.total_reparsed_modules = 0
        self.last_changes = ChangeSet(frozenset(), frozenset(), frozenset())
        self.last_impact = ImpactGraph(frozenset())

    def analyze(self, request: AnalysisRequest, *, workers: int = 1) -> AnalysisSnapshot:
        if workers < 1:
            raise ValueError("analysis workers must be positive")
        identity = (
            request.project_root.value.resolve(),
            request.resolver,
            tuple(request.adapter_versions.items()),
            request.language,
        )
        changes = ChangeSet.compare(self._sources, request.sources)
        reusable = self._request_identity == identity and bool(self._results)
        if not reusable:
            old_modules = frozenset(source.module_id for source in self._sources)
            new_modules = frozenset(source.module_id for source in request.sources)
            changes = ChangeSet(
                new_modules - old_modules, new_modules & old_modules, old_modules - new_modules
            )
            self._results.clear()
            impacted = {source.module_id for source in request.sources}
        else:
            impacted = set(changes.touched)
        self.last_changes = changes
        if reusable and not changes.touched and self._snapshot is not None:
            self._sources = request.sources
            self.reparsed_modules = 0
            self.last_impact = ImpactGraph(frozenset())
            return self._snapshot
        current = {source.module_id: source for source in request.sources}
        self._results = {
            module: result for module, result in self._results.items() if module in current
        }
        pending = tuple(current[module] for module in sorted(impacted) if module in current)
        fresh = self._adapter.analyze_modules(pending, request.resolver, workers)
        self.reparsed_modules = len(fresh)
        self.total_reparsed_modules += self.reparsed_modules
        self._results.update(zip((source.module_id for source in pending), fresh, strict=True))
        old_index = self._snapshot.project if self._snapshot is not None else None
        self._sources = request.sources
        self._request_identity = identity
        self._snapshot = ProjectAnalyzer.assemble(
            request, tuple(self._results[source.module_id] for source in request.sources)
        )
        self.last_impact = ImpactGraph.from_indexes(changes, old_index, self._snapshot.project)
        if not reusable:
            self.last_impact = ImpactGraph(
                frozenset(changes.touched)
                | frozenset(source.module_id for source in request.sources)
            )
        return self._snapshot
