from __future__ import annotations

import hashlib
import json

from taut.analysis.contracts import AnalysisRequest, LanguageAdapter
from taut.analysis.project_index import build_project_index
from taut.domain.facts import CompletenessState, ModuleFacts
from taut.domain.frozen import FrozenMap
from taut.domain.ids import SnapshotId
from taut.domain.issues import EngineIssue
from taut.domain.snapshot import (
    AnalysisCoverage,
    AnalysisInputDigest,
    AnalysisSnapshot,
)


class ProjectAnalyzer:
    def __init__(self, adapter: LanguageAdapter) -> None:
        self._adapter = adapter

    def analyze(self, request: AnalysisRequest, *, workers: int = 1) -> AnalysisSnapshot:
        if workers < 1:
            raise ValueError("analysis workers must be positive")
        modules: list[ModuleFacts] = []
        issues: list[EngineIssue] = []
        results = self._adapter.analyze_modules(request.sources, request.resolver, workers)
        for result in results:
            modules.append(result.facts)
            issues.extend(result.issues)

        module_map = FrozenMap((facts.module.id, facts) for facts in modules)
        project = build_project_index(modules)
        states = tuple(facts.completeness.state for facts in modules)
        coverage = AnalysisCoverage(
            requested_sources=len(request.sources),
            complete_modules=states.count(CompletenessState.COMPLETE),
            partial_modules=states.count(CompletenessState.PARTIAL),
            failed_modules=states.count(CompletenessState.FAILED),
        )
        digest = _analysis_digest(request)
        return AnalysisSnapshot(
            id=SnapshotId(digest),
            inputs=AnalysisInputDigest(digest),
            modules=module_map,
            project=project,
            capabilities=FrozenMap(),
            coverage=coverage,
            issues=tuple(issues),
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
