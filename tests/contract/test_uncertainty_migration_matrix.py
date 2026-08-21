from __future__ import annotations

import json
from pathlib import Path

import pytest

from taut.policy.rules import builtin_rule_registry

MATRIX_PATH = (
    Path(__file__).resolve().parents[2]
    / "docs/refactoring/backend-taut/uncertainty-migration-matrix.json"
)
UNCERTAINTY_STATES = ("resolved", "conditional", "ambiguous", "unresolved", "dynamic")


@pytest.mark.contract
def test_uncertainty_matrix_covers_exact_builtin_registry_once() -> None:
    matrix = json.loads(MATRIX_PATH.read_text())
    rows = matrix["rules"]
    registry_ids = {rule_id.value for rule_id in builtin_rule_registry().definitions}
    row_ids = [row["id"] for row in rows]
    states = set(matrix["state_values"])
    verdicts = set(matrix["verdict_values"])
    required = {
        "id",
        "source_module",
        "evaluator",
        "target",
        "syntax_only",
        "semantic_facts_consumed",
        "resolution_source",
        "resolution_policy",
        "missing_capability_completeness",
        "current_code_evidence",
        "required_code_test_change",
        "heuristic_provider_migration",
        "implementation_group",
        "group_files",
        "dependencies",
    }
    required_missing = {
        "missing_capability",
        "incomplete_project",
        "insufficient_analysis_stage",
        "missing_required_fact",
    }
    assert matrix["expected_builtin_count"] == 48
    assert len(registry_ids) == 48
    assert len(rows) == 48
    assert len(row_ids) == len(set(row_ids))
    assert set(row_ids) == registry_ids
    assert {row["target"] for row in rows} <= {"module", "symbol", "call", "operation", "project"}
    assert {row["implementation_group"] for row in rows} == set(matrix["groups"])
    for row in rows:
        assert required <= row.keys()
        assert row["source_module"].startswith("src/taut/policy/rules/")
        assert row["evaluator"]["class"] and row["evaluator"]["function"]
        assert row["semantic_facts_consumed"]
        assert set(row["resolution_policy"]) == states
        assert set(row["resolution_policy"].values()) <= verdicts | {"evaluate"}
        assert required_missing <= row["missing_capability_completeness"].keys()
        assert set(row["missing_capability_completeness"].values()) == {"indeterminate"}
        assert row["current_code_evidence"]["module"] == row["source_module"]
        if row["syntax_only"]:
            assert set(row["resolution_policy"].values()) == {"not_applicable"}
        elif row["id"] not in {"ADAPTER002", "ARCH000"}:
            assert any(value == "indeterminate" for value in row["resolution_policy"].values()), (
                row["id"]
            )


@pytest.mark.contract
def test_uncertainty_matrix_groups_are_disjoint_and_dependency_ordered() -> None:
    matrix = json.loads(MATRIX_PATH.read_text())
    grouped: dict[str, set[str]] = {group: set() for group in matrix["groups"]}
    for row in matrix["rules"]:
        assert row["id"] not in grouped[row["implementation_group"]]
        grouped[row["implementation_group"]].add(row["id"])
        assert row["source_module"] in matrix["groups"][row["implementation_group"]]["files"]
        assert row["group_files"] == matrix["groups"][row["implementation_group"]]["files"]
    assert sum(len(ids) for ids in grouped.values()) == 48
    assert all(9 <= len(ids) <= 16 for ids in grouped.values())
    assert len({path for group in matrix["groups"].values() for path in group["files"]}) == sum(
        len(group["files"]) for group in matrix["groups"].values()
    )
    for name, group in matrix["groups"].items():
        assert set(group["depends_on"]) < set(matrix["groups"])
        assert name not in group["depends_on"]


@pytest.mark.contract
@pytest.mark.parametrize(
    "rule_id", [rule_id.value for rule_id in builtin_rule_registry().definitions]
)
@pytest.mark.parametrize("state", UNCERTAINTY_STATES)
def test_every_builtin_rule_has_explicit_state_policy(rule_id: str, state: str) -> None:
    matrix = json.loads(MATRIX_PATH.read_text())
    row = next(item for item in matrix["rules"] if item["id"] == rule_id)
    assert row["resolution_policy"][state] in {"evaluate", "indeterminate", "not_applicable"}
    assert row["missing_capability_completeness"]["missing_capability"] == "indeterminate"
    assert row["missing_capability_completeness"]["incomplete_project"] == "indeterminate"
