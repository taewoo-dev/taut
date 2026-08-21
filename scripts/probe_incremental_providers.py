"""Read-only anti-monitor incremental provider probe."""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from dataclasses import replace
from pathlib import Path

from taut.analysis.contracts import AnalysisRequest, LanguageSettings, ProjectRoot, ResolverSettings
from taut.analysis.framework.fastapi import FastAPIProvider
from taut.analysis.python.language_adapter import PythonAstAdapter
from taut.domain.frozen import FrozenMap
from taut.incremental import IncrementalProjectAnalyzer
from taut.loading.config_loader import load_project_configuration
from taut.loading.source_discovery import discover_sources


def _git_status(root: Path) -> str:
    return subprocess.run(
        ("git", "status", "--porcelain=v1"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def main() -> int:
    root = Path(
        "/Users/taewoo/orca/workspaces/anti-monitor/backend-taut-compliance/backend"
    ).resolve()
    status_before = _git_status(root)
    config = load_project_configuration(root)
    before = discover_sources(root, config)
    adapter = PythonAstAdapter()
    analyzer = IncrementalProjectAnalyzer(adapter)
    req = AnalysisRequest(
        ProjectRoot(root),
        before.sources,
        LanguageSettings(),
        ResolverSettings(source_roots=config.source_roots),
        FrozenMap(((adapter.identity.name, adapter.identity.version),)),
    )
    old = analyzer.analyze(req, workers=4)
    provider = FastAPIProvider()
    previous = provider.analyze(old)
    ordinary = min(
        (source for source in before.sources if not source.is_package),
        key=lambda source: (
            len(old.project.imported_by.get(source.module_id, ())),
            source.path.value,
        ),
    )
    changed_content = ordinary.content + "\n# pytaut incremental provider probe\n"
    changed_source = replace(
        ordinary,
        content=changed_content,
        content_hash=hashlib.sha256(changed_content.encode()).hexdigest(),
    )
    changed_sources = tuple(
        changed_source if source.module_id == ordinary.module_id else source
        for source in before.sources
    )
    updated = analyzer.analyze(replace(req, sources=changed_sources))
    impacted = analyzer.last_impact.impacted
    started = time.perf_counter()
    incremental = provider.analyze_incremental(updated, previous, impacted)
    incremental_seconds = time.perf_counter() - started
    started = time.perf_counter()
    full = provider.analyze(updated)
    full_seconds = time.perf_counter() - started
    status_after = _git_status(root)
    parity = incremental == full
    speedup = full_seconds / max(incremental_seconds, 1e-9)
    mismatches = {
        name: {
            "full": len(full.get(name, ())),
            "incremental": len(incremental.get(name, ())),
        }
        for name in full
        if full.get(name, ()) != incremental.get(name, ())
    }
    print(
        json.dumps(
            {
                "discovered": len(before.sources),
                "reparsed_modules": analyzer.reparsed_modules,
                "impacted_modules": sorted(item.value for item in impacted),
                "ordinary_path": ordinary.path.value,
                "full_fastapi_seconds": full_seconds,
                "incremental_fastapi_seconds": incremental_seconds,
                "speedup": speedup,
                "capability_parity": parity,
                "external_status_unchanged": status_before == status_after,
                "mismatches": mismatches,
            },
            sort_keys=True,
        )
    )
    return (
        0
        if parity
        and analyzer.reparsed_modules == 1
        and incremental_seconds <= 1
        and speedup >= 3
        and status_before == status_after
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
