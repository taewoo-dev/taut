from dataclasses import replace

from tests.utils.builders import analyze, make_source

from taut.assurance_symbols import policy_symbol_issues
from taut.configuration.assurance import AssuranceConfiguration, FeatureExpectation
from taut.configuration.model import ProjectConfiguration
from taut.domain.frozen import FrozenMap
from taut.domain.ids import SymbolId
from taut.loading.default_configuration import default_project_configuration


def _dto_config(symbol: str) -> ProjectConfiguration:
    config = default_project_configuration()
    return replace(
        config,
        assurance=AssuranceConfiguration(FrozenMap((("dto", FeatureExpectation.REQUIRED),))),
        policy=replace(
            config.policy,
            code=replace(
                config.policy.code,
                dto_base_symbols=frozenset({SymbolId(symbol)}),
            ),
        ),
    )


def test_policy_symbol_liveness_requires_an_exact_symbol() -> None:
    snapshot = analyze(make_source("app/contracts.py", "class BaseResult: pass"))

    issues = policy_symbol_issues(_dto_config("app.contracts.Base"), snapshot)

    assert [item.code for item in issues] == ["POLICY_SYMBOL_UNRESOLVED"]


def test_policy_symbol_liveness_rejects_wrong_local_kind() -> None:
    snapshot = analyze(make_source("app/contracts.py", "DTO_BASE = object()"))

    issues = policy_symbol_issues(_dto_config("app.contracts.DTO_BASE"), snapshot)

    assert [item.code for item in issues] == ["POLICY_SYMBOL_KIND_MISMATCH"]
