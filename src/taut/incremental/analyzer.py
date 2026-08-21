from __future__ import annotations

from taut.analysis.contracts import (
    AnalysisRequest,
    LanguageAdapter,
    ModuleAnalysisResult,
    SourceInput,
)
from taut.analysis.project_analyzer import ProjectAnalyzer
from taut.domain.snapshot import AnalysisSnapshot
from taut.incremental.changes import ChangeSet, ImpactGraph


class IncrementalProjectAnalyzer:
    def __init__(self, adapter: LanguageAdapter) -> None:
        self._adapter = adapter
        self._results: dict[object, ModuleAnalysisResult] = {}
        self._sources: tuple[SourceInput, ...] = ()
        self._request_identity: tuple[object, ...] | None = None
        self._snapshot: AnalysisSnapshot | None = None
        self.reparsed_modules = 0

    def analyze(self, request: AnalysisRequest, *, workers: int = 1) -> AnalysisSnapshot:
        identity = (request.resolver, tuple(request.adapter_versions.items()), request.language)
        changes = ChangeSet.compare(self._sources, request.sources)
        reusable = self._request_identity == identity and bool(self._results)
        if not reusable:
            self._results.clear()
            impacted = {source.module_id for source in request.sources}
        else:
            impacted = set(
                ImpactGraph.from_indexes(
                    changes, self._snapshot.project if self._snapshot else None, None
                ).impacted
            )
        current = {source.module_id: source for source in request.sources}
        self._results = {
            module: result for module, result in self._results.items() if module in current
        }
        pending = tuple(current[module] for module in sorted(impacted) if module in current)
        fresh = self._adapter.analyze_modules(pending, request.resolver, workers)
        self.reparsed_modules = len(fresh)
        self._results.update(zip((source.module_id for source in pending), fresh, strict=True))
        self._sources = request.sources
        self._request_identity = identity
        self._snapshot = ProjectAnalyzer.assemble(
            request, tuple(self._results[source.module_id] for source in request.sources)
        )
        return self._snapshot
