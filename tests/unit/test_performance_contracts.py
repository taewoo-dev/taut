from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import cast

from scripts.benchmark_performance import (
    BASELINE_SCHEMA,
    TimedProvider,
    benchmark_revision,
    compare,
    measure,
    process_rss_bytes,
    real_checkout,
    request_for,
    rss_bytes,
)

from taut.analysis.framework.indexes import grouped
from taut.analysis.project_analyzer import ProjectAnalyzer
from taut.analysis.providers import FactProviderV1, apply_fact_providers
from taut.analysis.python.language_adapter import PythonAstAdapter
from taut.domain.frozen import FrozenMap
from taut.domain.snapshot import AnalysisSnapshot
from taut.policy.packs import builtin_backend_providers


def test_representative_fixtures_have_stable_digest_and_no_engine_issues() -> None:
    request = request_for(8, mixed=True)
    analyzer = ProjectAnalyzer(PythonAstAdapter())
    first = apply_fact_providers(analyzer.analyze(request), builtin_backend_providers())
    second = apply_fact_providers(analyzer.analyze(request), builtin_backend_providers())

    assert first.id == second.id
    assert first.modules == second.modules
    assert first.issues == second.issues == ()


def test_all_builtin_providers_are_invoked_once_per_snapshot() -> None:
    request = request_for(8, mixed=True)
    snapshot = ProjectAnalyzer(PythonAstAdapter()).analyze(request)

    class SpyProvider:
        def __init__(self, delegate: FactProviderV1) -> None:
            self.delegate = delegate
            self.calls = 0
            self.id = delegate.id
            self.version = delegate.version
            self.provides = delegate.provides

        def analyze(self, snapshot: AnalysisSnapshot) -> FrozenMap[str, tuple[object, ...]]:
            self.calls += 1
            return self.delegate.analyze(snapshot)

    providers = tuple(SpyProvider(provider) for provider in builtin_backend_providers())
    result = apply_fact_providers(snapshot, providers)
    assert result.coverage.unavailable_capabilities == ()
    assert all(provider.calls == 1 for provider in providers)


def test_rss_conversion_is_platform_correct() -> None:
    assert rss_bytes(2_000_000, system="darwin") == 2_000_000
    assert rss_bytes(2_000, system="linux") == 2_048_000


def test_current_process_rss_is_available() -> None:
    assert process_rss_bytes(os.getpid()) > 0


def test_benchmark_revision_changes_only_fixed_width_marker() -> None:
    seed = "value = 1\n# pytaut-benchmark-ordinary=00000000\n"
    revised = benchmark_revision(seed, "# pytaut-benchmark-ordinary=", 42)
    assert revised == "value = 1\n# pytaut-benchmark-ordinary=00000042\n"
    assert len(revised) == len(seed)


def test_measurement_runs_policy_engine_and_reports_real_engine_issues() -> None:
    measurement = measure(request_for(8, mixed=True))
    assert measurement.analysis_issues == 0
    assert measurement.engine_issues == 0
    assert len(measurement.snapshot_digest) == 64


def test_baseline_comparison_uses_medians_and_ci_thresholds() -> None:
    baseline = {
        "schema": BASELINE_SCHEMA,
        "results": [
            {
                "scale": "small",
                "repeats": [
                    {"wall_seconds": 0.10, "rss_bytes": 2_000_000},
                    {"wall_seconds": 0.12, "rss_bytes": 2_200_000},
                    {"wall_seconds": 0.11, "rss_bytes": 2_100_000},
                ],
            }
        ],
    }
    current = {
        "results": [
            {
                "scale": "small",
                "repeats": [
                    {"wall_seconds": 0.11, "rss_bytes": 2_100_000},
                    {"wall_seconds": 0.10, "rss_bytes": 2_000_000},
                    {"wall_seconds": 0.12, "rss_bytes": 2_200_000},
                ],
            }
        ]
    }
    comparison = compare(cast(dict[str, object], current), cast(dict[str, object], baseline))
    assert comparison == {"schema": BASELINE_SCHEMA, "passed": True, "violations": []}


def test_benchmark_request_is_sorted_and_digest_changes_only_with_sources() -> None:
    small = request_for(8, mixed=False)
    larger = request_for(32, mixed=False)
    assert tuple(source.path.value for source in small.sources) == tuple(
        sorted(source.path.value for source in small.sources)
    )
    assert small.sources != larger.sources
    assert (
        ProjectAnalyzer(PythonAstAdapter()).analyze(small).id
        != ProjectAnalyzer(PythonAstAdapter()).analyze(larger).id
    )


def test_timed_provider_preserves_contract_and_records_duration() -> None:
    provider = builtin_backend_providers()[0]
    timings: dict[str, float] = {}
    timed = TimedProvider(provider, timings)
    assert timed.id == provider.id
    assert timed.version == provider.version
    assert timed.provides == provider.provides
    timed.analyze(ProjectAnalyzer(PythonAstAdapter()).analyze(request_for(1, mixed=False)))
    assert provider.id in timings and timings[provider.id] >= 0


def test_real_checkout_timing_schema_and_provider_ids_are_stable(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[tool.taut]\nschema_version=5\nstrict=false\ninclude=["app/*.py"]\nsource_roots=["."]\n'
    )
    (tmp_path / "app").mkdir()
    (tmp_path / "app/main.py").write_text("value = 1\n")
    result = real_checkout(tmp_path, requested=1)
    measurement = cast(dict[str, object], result["measurement"])
    assert set(cast(dict[str, float], measurement["phase_timings"])) == {
        "config_discovery",
        "ast_analysis",
        "configured_providers",
        "classification_policy",
        "ignore_finding_processing",
    }
    assert set(cast(dict[str, float], measurement["provider_timings"])) == {
        "taut.python-core",
        "taut.fastapi",
        "taut.pydantic",
        "taut.pytest",
        "taut.sqlalchemy",
        "taut.tortoise",
    }
    assert result["status"] == "complete" and result["engine_issues"] == 0


def test_real_checkout_aggregates_inline_ignore_issue(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[tool.taut]\nschema_version=5\nstrict=false\ninclude=["app/*.py"]\nsource_roots=["."]\n'
    )
    (tmp_path / "app").mkdir()
    (tmp_path / "app/main.py").write_text("value = 1  # taut: ignore\n")
    result = real_checkout(tmp_path, requested=1)
    assert cast(int, result["complete"]) == 1 and cast(int, result["engine_issues"]) >= 1
    assert result["status"] != "complete"


def test_pydantic_index_builder_is_one_pass() -> None:
    class Counting:
        def __init__(self, items: list[tuple[int, int]]) -> None:
            self.items, self.visits = items, 0

        def __iter__(self) -> Iterator[tuple[int, int]]:
            for item in self.items:
                self.visits += 1
                yield item

    items = Counting([(i % 3, i) for i in range(150)])
    assert len(grouped(items, lambda item: item[0])) == 3 and items.visits == 150


def test_fastapi_index_builder_is_one_pass() -> None:
    class Counting:
        def __init__(self, items: list[tuple[int, int]]) -> None:
            self.items, self.visits = items, 0

        def __iter__(self) -> Iterator[tuple[int, int]]:
            for item in self.items:
                self.visits += 1
                yield item

    items = Counting([(i % 5, i) for i in range(125)])
    assert len(grouped(items, lambda item: item[0])) == 5 and items.visits == 125


def test_sqlalchemy_index_builder_is_one_pass() -> None:
    class Counting:
        def __init__(self, items: list[tuple[int, int]]) -> None:
            self.items, self.visits = items, 0

        def __iter__(self) -> Iterator[tuple[int, int]]:
            for item in self.items:
                self.visits += 1
                yield item

    items = Counting([(i % 7, i) for i in range(140)])
    assert len(grouped(items, lambda item: item[0])) == 7 and items.visits == 140
