from __future__ import annotations

import json
from pathlib import Path

import pytest

from taut.policy.rules import builtin_rule_registry

MATRIX_PATH = (
    Path(__file__).resolve().parents[2]
    / "docs/refactoring/backend-taut/uncertainty-migration-matrix.json"
)


@pytest.mark.contract
def test_uncertainty_matrix_covers_exact_builtin_registry_once() -> None:
    matrix = json.loads(MATRIX_PATH.read_text())
    rows = matrix["rules"]
    registry_ids = {rule_id.value for rule_id in builtin_rule_registry().definitions}
    row_ids = [row["id"] for row in rows]
    assert matrix["expected_builtin_count"] == 48
    assert len(registry_ids) == 48
    assert len(rows) == 48
    assert len(row_ids) == len(set(row_ids))
    assert set(row_ids) == registry_ids
    assert {row["target"] for row in rows} <= {"module", "symbol", "call", "operation", "project"}
    assert {row["group"] for row in rows} == set(matrix["groups"])
    allowed_maps = {
        "not_applicable",
        "resolved=evaluate; conditional/ambiguous/unresolved/dynamic=not_applicable",
        "resolved=evaluate; conditional/ambiguous/unresolved/dynamic=indeterminate",
        (
            "resolved=evaluate; conditional/ambiguous/unresolved/dynamic="
            "indeterminate_if_suffix_else_not_applicable"
        ),
        (
            "resolved=evaluate; conditional/ambiguous/unresolved/dynamic="
            "indeterminate_if_db_owner_suffix_else_not_applicable"
        ),
    }
    assert {row["resolution_map"] for row in rows} <= allowed_maps


@pytest.mark.contract
def test_uncertainty_matrix_groups_are_disjoint_and_dependency_ordered() -> None:
    matrix = json.loads(MATRIX_PATH.read_text())
    grouped = {group: set() for group in matrix["groups"]}
    for row in matrix["rules"]:
        assert row["id"] not in grouped[row["group"]]
        grouped[row["group"]].add(row["id"])
    assert not (grouped["A"] & grouped["B"])
    assert not (grouped["A"] & grouped["C"])
    assert not (grouped["A"] & grouped["D"])
    assert not (grouped["B"] & grouped["C"])
    assert not (grouped["B"] & grouped["D"])
    assert not (grouped["C"] & grouped["D"])
