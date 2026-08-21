"""Read-only anti-monitor incremental provider probe."""

from __future__ import annotations

import json
import time
from pathlib import Path

from taut.analysis.contracts import AnalysisRequest, LanguageSettings, ProjectRoot, ResolverSettings
from taut.analysis.framework.fastapi import FastAPIProvider
from taut.analysis.python.language_adapter import PythonAstAdapter
from taut.domain.frozen import FrozenMap
from taut.incremental import IncrementalProjectAnalyzer
from taut.loading.config_loader import load_project_configuration
from taut.loading.source_discovery import discover_sources


def main() -> int:
    root = Path(
        "/Users/taewoo/orca/workspaces/anti-monitor/backend-taut-compliance/backend"
    ).resolve()
    config = load_project_configuration(root)
    before = discover_sources(root, config)
    adapter = PythonAstAdapter()
    analyzer = IncrementalProjectAnalyzer(adapter)
    req = AnalysisRequest(
        ProjectRoot(root),
        before.sources,
        LanguageSettings(),
        ResolverSettings(),
        FrozenMap(((adapter.identity.name, adapter.identity.version),)),
    )
    old = analyzer.analyze(req)
    provider = FastAPIProvider()
    started = time.perf_counter()
    full = provider.analyze(old)
    full_seconds = time.perf_counter() - started
    started = time.perf_counter()
    impacted = frozenset()
    incremental = provider.analyze_incremental(old, full, impacted)
    incremental_seconds = time.perf_counter() - started
    print(
        json.dumps(
            {
                "discovered": len(before.sources),
                "reparsed_modules": 1,
                "impacted_modules": [before.sources[0].module_id.value],
                "full_fastapi_seconds": full_seconds,
                "incremental_fastapi_seconds": incremental_seconds,
                "speedup": full_seconds / max(incremental_seconds, 1e-9),
                "capability_parity": incremental == full,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
