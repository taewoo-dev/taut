from __future__ import annotations

from pathlib import Path

import pytest
from scripts.check_conventions import main as check_conventions

from taut.policy.rules import builtin_rule_registry


@pytest.mark.contract
def test_repository_conventions_are_currently_satisfied() -> None:
    check_conventions()


@pytest.mark.contract
def test_every_builtin_rule_fixture_exists() -> None:
    root = Path(__file__).resolve().parents[2]
    registry = builtin_rule_registry()

    for definition in registry.definitions.values():
        for relative in (*definition.compliant_fixtures, *definition.violation_fixtures):
            assert (root / relative).exists(), f"missing fixture: {relative}"
