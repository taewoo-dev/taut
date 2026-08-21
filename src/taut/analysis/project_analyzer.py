from __future__ import annotations

import hashlib
import json

from taut.analysis.contracts import AnalysisRequest, LanguageAdapter, ModuleAnalysisResult
from taut.analysis.project_index import build_project_index
from taut.analysis.project_relations import build_project_relations
from taut.domain.facts import CompletenessState, ModuleFacts, ResolutionState
from taut.domain.frozen import FrozenMap
from taut.domain.ids import SnapshotId
from taut.domain.issues import EngineIssue
from taut.domain.relations import ModuleRelations
from taut.domain.snapshot import (
    AnalysisCoverage,
    AnalysisInputDigest,
    AnalysisSnapshot,
    ResolutionCoverage,
)


class ProjectAnalyzer:
    def __init__(self, adapter: LanguageAdapter) -> None:
        self._adapter = adapter

    def analyze(self, request: AnalysisRequest, *, workers: int = 1) -> AnalysisSnapshot:
        if workers < 1:
            raise ValueError("analysis workers must be positive")
        results = self._adapter.analyze_modules(request.sources, request.resolver, workers)
        return self.assemble(request, results)

    @staticmethod
    def assemble(
        request: AnalysisRequest, results: tuple[ModuleAnalysisResult, ...]
    ) -> AnalysisSnapshot:
        modules: list[ModuleFacts] = []
        module_relations: list[ModuleRelations] = []
        issues: list[EngineIssue] = []
        for result in results:
            modules.append(result.facts)
            module_relations.append(result.relations)
            issues.extend(result.issues)

        module_map = FrozenMap((facts.module.id, facts) for facts in modules)
        project = build_project_index(modules)
        relations = build_project_relations(module_map, project, tuple(module_relations))
        states = tuple(facts.completeness.state for facts in modules)
        calls = tuple(call for facts in modules for call in facts.calls)
        references = tuple(reference for facts in modules for reference in facts.references)
        coverage = AnalysisCoverage(
            requested_sources=len(request.sources),
            complete_modules=states.count(CompletenessState.COMPLETE),
            partial_modules=states.count(CompletenessState.PARTIAL),
            failed_modules=states.count(CompletenessState.FAILED),
            calls=_resolution_coverage(tuple(call.ref.state for call in calls)),
            references=_resolution_coverage(tuple(reference.ref.state for reference in references)),
            resolved_imports=len(project.import_edges),
            unresolved_imports=len(project.unresolved_imports),
        )
        digest = _analysis_digest(request)
        return AnalysisSnapshot(
            id=SnapshotId(digest),
            inputs=AnalysisInputDigest(digest),
            modules=module_map,
            project=project,
            relations=relations,
            capabilities=FrozenMap(),
            coverage=coverage,
            issues=tuple(issues),
        )


def _resolution_coverage(states: tuple[ResolutionState, ...]) -> ResolutionCoverage:
    return ResolutionCoverage(
        resolved=states.count(ResolutionState.RESOLVED),
        conditional=states.count(ResolutionState.CONDITIONAL),
        ambiguous=states.count(ResolutionState.AMBIGUOUS),
        unresolved=states.count(ResolutionState.UNRESOLVED),
        dynamic=states.count(ResolutionState.DYNAMIC),
    )


def _analysis_digest(request: AnalysisRequest) -> str:
    payload = {
        "sources": [
            {
                "path": source.path.value,
                "module": source.module_id.value,
                "kind": source.kind.value,
                "target": source.is_policy_target,
                "hash": source.content_hash,
            }
            for source in request.sources
        ],
        "language": {
            "name": request.language.language,
            "target_version": request.language.target_version,
        },
        "resolver": {
            "source_roots": [root.value for root in request.resolver.source_roots],
            "context_manager_providers": [
                (provider.symbol.value, provider.item_type.value)
                for provider in request.resolver.context_manager_providers
            ],
        },
        "adapters": list(request.adapter_versions.items()),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
