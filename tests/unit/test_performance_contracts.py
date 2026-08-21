from __future__ import annotations

from typing import cast

from scripts.benchmark_performance import BASELINE_SCHEMA, compare, measure, request_for, rss_bytes

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
