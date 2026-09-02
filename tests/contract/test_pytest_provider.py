from typing import cast

from tests.utils.builders import analyze, make_source

from taut.analysis.framework.pytest import PYTEST_FIXTURES, PytestFixtureFact, PytestProvider
from taut.analysis.providers import apply_fact_providers, apply_fact_providers_incremental
from taut.domain.ids import ModuleId
from taut.domain.snapshot import AnalysisSnapshot
from taut.plugins.v1 import PytestProvider as PublicPytestProvider


def _snapshot(source: str) -> AnalysisSnapshot:
    return analyze(make_source("tests/conftest.py", source))


def test_pytest_provider_extracts_fixture_provenance_and_dependencies() -> None:
    result = apply_fact_providers(
        _snapshot(
            """import pytest

@pytest.fixture
def transport():
    return object()

@pytest.fixture()
def api_client(transport):
    return transport
"""
        ),
        (PytestProvider(),),
    )
    fixtures = cast(tuple[PytestFixtureFact, ...], result.capabilities[PYTEST_FIXTURES])

    assert [(item.name, item.dependencies) for item in fixtures] == [
        ("api_client", ("transport",)),
        ("transport", ()),
    ]
    assert all(item.provenance.source_hash for item in fixtures)


def test_pytest_provider_incremental_result_matches_full_analysis() -> None:
    provider = PytestProvider()
    original = _snapshot("import pytest\n@pytest.fixture\ndef first(): return 1\n")
    changed = _snapshot(
        "import pytest\n@pytest.fixture\ndef first(): return 1\n"
        "@pytest.fixture\ndef second(first): return first\n"
    )
    previous = apply_fact_providers(original, (provider,))
    incremental = apply_fact_providers_incremental(
        changed, (provider,), previous, frozenset({ModuleId("tests.conftest")})
    )
    full = apply_fact_providers(changed, (provider,))

    assert incremental.capabilities == full.capabilities


def test_pytest_provider_is_public_plugin_contract() -> None:
    provider = PublicPytestProvider()
    assert provider.id == "taut.pytest"
    assert provider.version == "1"
    assert {item.id for item in provider.provides} == {PYTEST_FIXTURES}
