"""Deterministic performance benchmark and read-only checkout probe."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import resource
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from taut.analysis.contracts import (
    AnalysisRequest,
    ContextManagerProvider,
    LanguageSettings,
    ProjectRoot,
    ResolverSettings,
    SourceInput,
)
from taut.analysis.project_analyzer import ProjectAnalyzer
from taut.analysis.providers import FactProviderV1, apply_fact_providers
from taut.analysis.python.language_adapter import PythonAstAdapter
from taut.analysis.semantic_model import SnapshotSemanticModel
from taut.configuration.catalog import EffectResolver
from taut.configuration.manifest import ProjectManifest, Role, RoleMatcher, Zone
from taut.configuration.validation import validate_classification_for_policy
from taut.domain.facts import SourceKind
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, SymbolId
from taut.domain.location import ConfigLocation, ProjectPath
from taut.domain.snapshot import AnalysisSnapshot
from taut.finding_processing.finding_processor import FindingProcessor
from taut.loading.config_loader import load_project_configuration
from taut.loading.default_configuration import default_project_configuration
from taut.loading.inline_ignores import load_inline_ignores
from taut.loading.source_discovery import discover_sources
from taut.policy.context import PolicyContext
from taut.policy.decision_digest import build_decision_digest
from taut.policy.engine import PolicyEngine, PolicyRunResult
from taut.policy.packs import (
    builtin_backend_pack,
    builtin_backend_providers,
    load_fact_provider,
    load_rule_pack,
)
from taut.policy.registry import RuleRegistry

SCALES = {"small": 8, "medium": 32, "large": 96}
BASELINE_SCHEMA = "pytaut-performance-baseline-v1"
# Additive schema note: existing result keys remain stable; cache_scenarios is optional.
WALL_FLOOR_SECONDS = 0.05
RSS_FLOOR_BYTES = 1 << 20


class TimedProvider:
    """Transparent provider wrapper; timing does not alter dependency semantics."""

    def __init__(self, provider: FactProviderV1, timings: dict[str, float]) -> None:
        self._provider = provider
        self._timings = timings

    def __getattr__(self, name: str) -> object:
        return getattr(self._provider, name)

    def analyze(self, snapshot: AnalysisSnapshot) -> FrozenMap[str, tuple[object, ...]]:
        started = time.perf_counter()
        result = self._provider.analyze(snapshot)
        self._timings[self._provider.id] = time.perf_counter() - started
        return result


def _source(index: int, mixed: bool) -> SourceInput:
    name = f"app/module_{index:03d}.py"
    if mixed and index % 3 == 0:
        body = f"""from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

router = APIRouter()
class Base(DeclarativeBase): pass
class Payload{index}(BaseModel):
    value: int
class Record{index}(Base):
    __tablename__ = 'record_{index}'
    id: Mapped[int] = mapped_column(primary_key=True)
@router.get('/{index}', response_model=Payload{index})
def endpoint_{index}() -> Payload{index}:
    return Payload{index}(value={index})
"""
    else:
        body = f"""from collections.abc import Iterable

class Service{index}:
    def values(self, items: Iterable[int]) -> list[int]:
        return [item + {index} for item in items]

def function_{index}(value: int = {index}) -> int:
    return Service{index}().values((value,))[0]
"""
    return SourceInput(
        ProjectPath(name),
        ModuleId(name.removesuffix(".py").replace("/", ".")),
        SourceKind.FIRST_PARTY,
        True,
        False,
        body,
        hashlib.sha256(body.encode()).hexdigest(),
    )


def request_for(count: int, *, mixed: bool) -> AnalysisRequest:
    adapter = PythonAstAdapter()
    return AnalysisRequest(
        ProjectRoot(Path("/pytaut-benchmark")),
        tuple(_source(i, mixed) for i in range(count)),
        LanguageSettings(),
        ResolverSettings(),
        FrozenMap(((adapter.identity.name, adapter.identity.version),)),
    )


def rss_bytes(raw: int, *, system: str | None = None) -> int:
    """Normalize ru_maxrss (bytes on macOS, KiB on Linux) to bytes."""
    return raw if (sys.platform if system is None else system) == "darwin" else raw * 1024


def _policy_result(snapshot: AnalysisSnapshot) -> PolicyRunResult:
    location = ConfigLocation(ProjectPath("benchmark.toml"))
    manifest = ProjectManifest(
        (RoleMatcher(Role("service"), ("app/*.py",), location),), (), Zone("prod"), location
    )
    config = default_project_configuration()
    context = PolicyContext(
        SnapshotSemanticModel(snapshot),
        manifest.classify(snapshot),
        EffectResolver(),
        config.catalog,
        config.policy,
    )
    return PolicyEngine(builtin_backend_pack().registry).run(context)


@dataclass(frozen=True)
class Measurement:
    wall_seconds: float
    rss_bytes: int
    sources_per_second: float
    snapshot_digest: str
    modules: int
    analysis_issues: int
    engine_issues: int


def measure(request: AnalysisRequest) -> Measurement:
    before = rss_bytes(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    started = time.perf_counter()
    snapshot = apply_fact_providers(
        ProjectAnalyzer(PythonAstAdapter()).analyze(request), builtin_backend_providers()
    )
    policy_result = _policy_result(snapshot)
    elapsed = time.perf_counter() - started
    after = rss_bytes(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return Measurement(
        elapsed,
        max(0, after - before),
        len(request.sources) / max(elapsed, 1e-9),
        snapshot.id.value,
        len(snapshot.modules),
        len(snapshot.issues),
        len(policy_result.engine_issues),
    )


def run(scale: str, *, mixed: bool, repeats: int) -> dict[str, object]:
    request = request_for(SCALES[scale], mixed=mixed)
    measurements = [measure(request) for _ in range(repeats)]
    return {
        "mode": "synthetic",
        "scale": scale,
        "fixture": "mixed-fastapi-sqlalchemy-pydantic" if mixed else "generic-python",
        "sources": len(request.sources),
        "repeats": [item.__dict__ for item in measurements],
        "deterministic_digest": len({item.snapshot_digest for item in measurements}) == 1,
    }


def _cache_scenarios(root: Path, cache_dir: Path, repeats: int = 3) -> dict[str, object]:
    """Measure CLI cache phases; fixture copy/edit happens outside timed regions."""
    cache_dir.mkdir(parents=True, exist_ok=True)

    def invoke(
        project: Path, use_cache: bool, directory: Path | None = None
    ) -> tuple[float, bytes, bytes, int]:
        command = [sys.executable, "-m", "taut.cli", "check", str(project)]
        if use_cache:
            command.extend(("--cache-dir", str(directory or cache_dir)))
        else:
            command.append("--no-cache")
        started = time.perf_counter()
        completed = subprocess.run(command, capture_output=True, check=False)
        return (
            time.perf_counter() - started,
            completed.stdout,
            completed.stderr,
            completed.returncode,
        )

    cold = [invoke(root, False) for _ in range(repeats)]
    first_fill = [
        invoke(root, True, cache_dir.parent / f"{cache_dir.name}-fill-{i}") for i in range(repeats)
    ]
    invoke(root, True, cache_dir)
    unchanged = [invoke(root, True, cache_dir) for _ in range(repeats)]
    ordinary: list[tuple[float, bytes, bytes, int]] = []
    shared: list[tuple[float, bytes, bytes, int]] = []
    parity: list[bool] = []
    with tempfile.TemporaryDirectory(prefix="pytaut-benchmark-") as copied:
        changed_root = Path(copied) / "project"
        shutil.copytree(root, changed_root)
        for index, source in enumerate(sorted(changed_root.rglob("*.py"))[:2]):
            for iteration in range(repeats):
                original = source.read_text(encoding="utf-8")
                source.write_text(
                    original + f"\n# benchmark edit {index}-{iteration}\n", encoding="utf-8"
                )
                canonical = invoke(changed_root, False)
                cached = invoke(changed_root, True, cache_dir)
                (ordinary if index == 0 else shared).append(cached)
                parity.append(canonical[1:] == cached[1:])
                source.write_text(original, encoding="utf-8")
    canonical = invoke(root, False)

    def timing(items: list[tuple[float, bytes, bytes, int]], label: str) -> dict[str, object]:
        values = sorted(item[0] for item in items)
        return {
            "median_wall_seconds": statistics.median(values),
            "p95_wall_seconds": values[-1],
            "cache": label,
        }

    return {
        "schema": "pytaut-cache-benchmark-v1",
        "phases": {
            "cold_no_cache": timing(cold, "no_cache"),
            "first_fill": timing(first_fill, "miss"),
            "no_change": timing(unchanged, "hit"),
            "ordinary_edit": timing(ordinary, "invalidation"),
            "shared_base_import_change": timing(shared, "invalidation"),
        },
        "counters": {
            "hits": repeats,
            "misses": repeats + 1,
            "invalidations": len(ordinary) + len(shared),
        },
        "stdout_digests": [hashlib.sha256(item[1]).hexdigest() for item in unchanged],
        "stderr_digests": [hashlib.sha256(item[2]).hexdigest() for item in unchanged],
        "canonical_no_cache_digest": hashlib.sha256(canonical[1]).hexdigest(),
        "cached_matches_canonical": all(parity),
        "cache_db_bytes": (cache_dir / "cache.sqlite3").stat().st_size
        if (cache_dir / "cache.sqlite3").exists()
        else 0,
        "peak_rss_bytes": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
    }


def real_checkout(
    root: Path, requested: int | None, *, cache_dir: Path | None = None
) -> dict[str, object]:
    root = root.resolve()
    phase_started = time.perf_counter()
    config = load_project_configuration(root)
    discovery = discover_sources(root, config)
    sources = discovery.sources
    phase_timings = {"config_discovery": time.perf_counter() - phase_started}
    adapter = PythonAstAdapter()
    context_manager_providers = tuple(
        sorted(
            {
                *(
                    ContextManagerProvider(symbol, SymbolId("sqlalchemy.ext.asyncio.AsyncSession"))
                    for symbol in config.policy.transaction_session_providers
                ),
                *(
                    ContextManagerProvider(symbol, symbol)
                    for symbol in config.policy.boundaries.http_timeout_calls
                ),
            }
        )
    )
    request = AnalysisRequest(
        ProjectRoot(root.resolve()),
        sources,
        LanguageSettings(),
        ResolverSettings(
            source_roots=config.source_roots,
            context_manager_providers=context_manager_providers,
        ),
        FrozenMap(((adapter.identity.name, adapter.identity.version),)),
    )
    before = rss_bytes(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    started = time.perf_counter()
    workers = min(8, max(1, (os.cpu_count() or 2) // 2))
    snapshot = ProjectAnalyzer(adapter).analyze(request, workers=workers)
    phase_timings["ast_analysis"] = time.perf_counter() - started
    phase_started = time.perf_counter()
    providers = tuple(load_fact_provider(provider_id) for provider_id in config.providers)
    provider_timings: dict[str, float] = {}
    timed_providers = tuple(TimedProvider(provider, provider_timings) for provider in providers)
    snapshot = apply_fact_providers(snapshot, cast(tuple[FactProviderV1, ...], timed_providers))
    phase_timings["configured_providers"] = time.perf_counter() - phase_started
    phase_started = time.perf_counter()
    classifications = config.manifest.classify(snapshot)
    validate_classification_for_policy(classifications, config.policy)
    context = PolicyContext(
        SnapshotSemanticModel(snapshot),
        classifications,
        EffectResolver(),
        config.catalog,
        config.policy,
    )
    packs = tuple(load_rule_pack(pack_id) for pack_id in config.packs)
    registry = RuleRegistry.build(
        definition for pack in packs for definition in pack.registry.definitions.values()
    )
    policy_result = PolicyEngine(registry).run(context)
    phase_timings["classification_policy"] = time.perf_counter() - phase_started
    phase_started = time.perf_counter()
    ignore_result = load_inline_ignores(sources, frozenset(registry.definitions))
    processing = FindingProcessor().process(
        findings=policy_result.findings,
        policy=config.policy,
        help_by_rule=FrozenMap(
            (rule_id, definition.help) for rule_id, definition in registry.definitions.items()
        ),
        ignores=ignore_result.directives,
    )
    phase_timings["ignore_finding_processing"] = time.perf_counter() - phase_started
    elapsed = time.perf_counter() - started
    after = rss_bytes(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    engine_issues = (
        *discovery.issues,
        *snapshot.issues,
        *policy_result.engine_issues,
        *processing.engine_issues,
        *ignore_result.issues,
    )
    measurement = {
        "wall_seconds": elapsed,
        "rss_bytes": max(0, after - before),
        "sources_per_second": len(sources) / max(elapsed, 1e-9),
        "snapshot_digest": snapshot.id.value,
        "modules": len(snapshot.modules),
        "analysis_issues": len(snapshot.issues),
        "engine_issues": len(engine_issues),
        "policy_digest": build_decision_digest(
            config, registry, adapter.identity, packs, providers
        ),
        "exit_relevant_indeterminate": policy_result.coverage.indeterminate,
        "phase_timings": phase_timings,
        "provider_timings": provider_timings,
    }
    counts = {
        "complete": snapshot.coverage.complete_modules,
        "partial": snapshot.coverage.partial_modules,
        "failed": snapshot.coverage.failed_modules,
    }
    expected = len(sources) if requested is None else requested
    status = (
        "complete"
        if (
            len(sources) == expected
            and counts["complete"] == expected
            and not counts["failed"]
            and not engine_issues
        )
        else "partial"
    )
    if not sources:
        status = "failed"
    result: dict[str, object] = {
        "mode": "real_checkout_read_only",
        "checkout": str(root.resolve()),
        "requested": expected,
        "discovered": len(sources),
        **counts,
        "status": status,
        "measurement": measurement,
        "files_read": len(sources),
        "discovery_issues": len(discovery.issues),
        "policy_engine_issues": len(policy_result.engine_issues),
        "engine_issues": len(engine_issues),
    }
    if cache_dir is not None:
        result["cache_scenarios"] = _cache_scenarios(root, cache_dir)
    return result


def _median(result: dict[str, object], metric: str) -> float:
    repeats = cast(list[dict[str, object]], result["repeats"])
    return float(statistics.median(float(cast(float | int, item[metric])) for item in repeats))


def compare(current: dict[str, object], baseline: dict[str, object]) -> dict[str, object]:
    violations: list[dict[str, object]] = []
    baseline_results = {
        item["scale"]: item for item in cast(list[dict[str, object]], baseline["results"])
    }
    for result in cast(list[dict[str, object]], current["results"]):
        prior = baseline_results[result["scale"]]
        for metric, threshold, floor in (
            ("wall_seconds", 2.0, WALL_FLOOR_SECONDS),
            ("rss_bytes", 3.0, RSS_FLOOR_BYTES),
        ):
            actual, expected = _median(result, metric), _median(prior, metric)
            if actual > floor and expected > 0 and actual > max(floor, expected * threshold):
                violations.append(
                    {
                        "scale": result["scale"],
                        "metric": metric,
                        "actual": actual,
                        "baseline": expected,
                        "ratio": actual / expected,
                    }
                )
    return {"schema": BASELINE_SCHEMA, "passed": not violations, "violations": violations}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scale", choices=(*tuple(SCALES), "all"), default="all")
    parser.add_argument("--generic", action="store_true")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--real-checkout", type=Path)
    parser.add_argument("--requested", type=int)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument(
        "--cache-dir", type=Path, help="directory for isolated cache benchmark data"
    )
    args = parser.parse_args(argv)
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    scales = tuple(SCALES) if args.scale == "all" else (args.scale,)
    output: dict[str, object] = {
        "schema": BASELINE_SCHEMA,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "processor": platform.processor(),
        "results": [run(scale, mixed=not args.generic, repeats=args.repeats) for scale in scales],
    }
    if args.real_checkout is not None:
        output["real_checkout"] = real_checkout(
            args.real_checkout, args.requested, cache_dir=args.cache_dir
        )
    if args.baseline is not None:
        output["comparison"] = compare(
            output, json.loads(args.baseline.read_text(encoding="utf-8"))
        )
    print(json.dumps(output, indent=2, sort_keys=True))
    comparison = output.get("comparison")
    if not isinstance(comparison, dict):
        return 0
    return 1 if not bool(cast(dict[str, object], comparison)["passed"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
