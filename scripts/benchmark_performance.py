"""Deterministic pytaut performance and anti-monitor benchmark.

The benchmark intentionally uses in-memory ``SourceInput`` values so it cannot
watch, mutate, or depend on an external checkout.  Its JSON output is suitable
for checking into CI artifacts (the machine metadata is deliberately separate
from the deterministic result digest).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import resource
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from taut.analysis.contracts import (
    AnalysisRequest,
    LanguageSettings,
    ProjectRoot,
    ResolverSettings,
    SourceInput,
)
from taut.analysis.project_analyzer import ProjectAnalyzer
from taut.analysis.providers import apply_fact_providers
from taut.analysis.python.language_adapter import PythonAstAdapter
from taut.domain.facts import SourceKind
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId
from taut.domain.location import ProjectPath
from taut.policy.packs import builtin_backend_providers

SCALES = {"small": 8, "medium": 32, "large": 96}
ANTI_MONITOR_SOURCES = 952


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
    digest = hashlib.sha256(body.encode()).hexdigest()
    return SourceInput(
        path=ProjectPath(name),
        module_id=ModuleId(name.removesuffix(".py").replace("/", ".")),
        kind=SourceKind.FIRST_PARTY,
        is_policy_target=True,
        is_package=False,
        content=body,
        content_hash=digest,
    )


def request_for(count: int, *, mixed: bool) -> AnalysisRequest:
    adapter = PythonAstAdapter()
    return AnalysisRequest(
        project_root=ProjectRoot(Path("/pytaut-benchmark")),
        sources=tuple(_source(index, mixed) for index in range(count)),
        language=LanguageSettings(),
        resolver=ResolverSettings(),
        adapter_versions=FrozenMap(((adapter.identity.name, adapter.identity.version),)),
    )


@dataclass(frozen=True)
class Measurement:
    wall_seconds: float
    rss_kib: int
    sources_per_second: float
    digest: str
    modules: int
    engine_issues: int


def measure(request: AnalysisRequest, *, warm: bool) -> Measurement:
    adapter = PythonAstAdapter()
    analyzer = ProjectAnalyzer(adapter)
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    started = time.perf_counter()
    snapshot = analyzer.analyze(request)
    snapshot = apply_fact_providers(snapshot, builtin_backend_providers())
    elapsed = time.perf_counter() - started
    after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # ru_maxrss is KiB on macOS and Linux; retain the platform's native unit.
    rss = max(0, int(after - before))
    return Measurement(
        wall_seconds=elapsed,
        rss_kib=rss,
        sources_per_second=len(request.sources) / max(elapsed, 1e-9),
        digest=snapshot.id.value,
        modules=len(snapshot.modules),
        engine_issues=len(snapshot.issues),
    )


def run(scale: str, *, mixed: bool, repeats: int, anti_monitor: bool = False) -> dict[str, object]:
    request = request_for(SCALES[scale], mixed=mixed)
    cold = [measure(request, warm=False) for _ in range(repeats)]
    warm = [measure(request, warm=True) for _ in range(repeats)]
    payload: dict[str, object] = {
        "scale": scale,
        "fixture": "mixed-fastapi-sqlalchemy-pydantic" if mixed else "generic-python",
        "sources": len(request.sources),
        "cold": [item.__dict__ for item in cold],
        "warm": [item.__dict__ for item in warm],
        "deterministic_digest": len({item.digest for item in cold + warm}) == 1,
        "anti_monitor": {
            "external_files_read": False,
            "external_files_written": False,
            "watch_processes": False,
        },
    }
    if anti_monitor:
        anti_request = request_for(ANTI_MONITOR_SOURCES, mixed=mixed)
        anti_measurement = measure(anti_request, warm=False)
        payload["anti_monitor_952"] = {
            "sources": ANTI_MONITOR_SOURCES,
            **anti_measurement.__dict__,
        }
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scale", choices=(*tuple(SCALES), "all"), default="all")
    parser.add_argument("--generic", action="store_true", help="also run generic fixtures")
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument(
        "--anti-monitor", action="store_true", help="also measure a 952-source no-watch run"
    )
    args = parser.parse_args(argv)
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    scales = tuple(SCALES) if args.scale == "all" else (args.scale,)
    results = [
        run(
            scale,
            mixed=not args.generic,
            repeats=args.repeats,
            anti_monitor=args.anti_monitor,
        )
        for scale in scales
    ]
    output = {
        "benchmark": "pytaut-performance-v1",
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "processor": platform.processor(),
        "results": results,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
