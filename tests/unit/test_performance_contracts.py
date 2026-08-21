from __future__ import annotations

from scripts.benchmark_performance import request_for

from taut.analysis.project_analyzer import ProjectAnalyzer
from taut.analysis.providers import CapabilitySpec, apply_fact_providers
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


def test_provider_pipeline_invokes_each_provider_once_per_snapshot() -> None:
    request = request_for(8, mixed=True)
    snapshot = ProjectAnalyzer(PythonAstAdapter()).analyze(request)

    class CountingProvider:
        id = "test.counting"
        version = "1"
        provides: frozenset[CapabilitySpec] = frozenset()
        calls = 0

        def analyze(self, snapshot: AnalysisSnapshot) -> FrozenMap[str, tuple[object, ...]]:
            self.calls += 1
            return FrozenMap()

    provider = CountingProvider()
    # An empty provider is valid and makes the invocation contract explicit.
    apply_fact_providers(snapshot, (provider,))
    assert provider.calls == 1


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
