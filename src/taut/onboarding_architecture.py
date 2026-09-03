"""Reviewable architecture decisions for the init contract."""

from __future__ import annotations

from typing import cast

from taut.loading.errors import PolicyConfigError


def architecture_policy(
    answers: dict[str, object] | None,
    observed: dict[str, set[str]],
) -> tuple[
    dict[str, set[str]],
    bool,
    tuple[tuple[str, str], ...],
    tuple[tuple[str, str, str, str], ...],
]:
    raw: object = {} if answers is None else answers.get("architecture", {})
    if not isinstance(raw, dict):
        raise PolicyConfigError("init answers.architecture must be an object")
    raw_table = cast(dict[object, object], raw)
    if not all(isinstance(key, str) for key in raw_table):
        raise PolicyConfigError("init answers.architecture must be an object")
    table = cast(dict[str, object], raw)
    unknown = set(table).difference({"accept_safe_observed_edges", "risky_edges"})
    if unknown:
        raise PolicyConfigError(f"unknown init architecture keys: {', '.join(sorted(unknown))}")
    accepted = table.get("accept_safe_observed_edges", False)
    if not isinstance(accepted, bool):
        raise PolicyConfigError(
            "init answers.architecture.accept_safe_observed_edges must be a boolean"
        )
    raw_decisions = table.get("risky_edges", [])
    if not isinstance(raw_decisions, list):
        raise PolicyConfigError("init answers.architecture.risky_edges must be an array")
    decisions: dict[tuple[str, str], tuple[str, str]] = {}
    for index, raw_decision in enumerate(cast(list[object], raw_decisions)):
        if not isinstance(raw_decision, dict):
            raise PolicyConfigError(f"init risky_edges[{index}] must be an object")
        raw_item = cast(dict[object, object], raw_decision)
        if not all(isinstance(key, str) for key in raw_item):
            raise PolicyConfigError(f"init risky_edges[{index}] must be an object")
        item = cast(dict[str, object], raw_decision)
        if set(item) != {"source", "target", "decision", "reason"}:
            raise PolicyConfigError("init risky edge requires source, target, decision, and reason")
        if not all(isinstance(value, str) and value.strip() for value in item.values()):
            raise PolicyConfigError("init risky edge values must be non-empty strings")
        source = cast(str, item["source"])
        target = cast(str, item["target"])
        decision = cast(str, item["decision"])
        reason = cast(str, item["reason"]).strip()
        edge = (source, target)
        if target not in observed.get(source, set()) or not is_risky_edge(source, target, observed):
            raise PolicyConfigError(f"init risky edge is not an observed risky edge: {edge}")
        if decision not in {"allow", "deny"}:
            raise PolicyConfigError("init risky edge decision must be allow or deny")
        if edge in decisions:
            raise PolicyConfigError(f"duplicate init risky edge decision: {edge}")
        decisions[edge] = (decision, reason)
    risky = {
        (source, target)
        for source, targets in observed.items()
        for target in targets
        if source != target and is_risky_edge(source, target, observed)
    }
    unresolved = tuple(sorted(risky.difference(decisions)))
    allowed = {source: set(targets) for source, targets in observed.items()}
    for (source, target), (decision, _) in decisions.items():
        if decision == "deny":
            allowed[source].discard(target)
    reviews = tuple(
        (source, target, decision, reason)
        for (source, target), (decision, reason) in sorted(decisions.items())
    )
    return allowed, accepted, unresolved, reviews


def is_risky_edge(source: str, target: str, graph: dict[str, set[str]]) -> bool:
    if source == target:
        return False
    if target in {"test", "migration", "script", "bootstrap", "router"}:
        return True
    if source == "application" or target == "application":
        return True
    visiting = [target]
    seen: set[str] = set()
    while visiting:
        current = visiting.pop()
        if current == source:
            return True
        if current in seen:
            continue
        seen.add(current)
        visiting.extend(graph.get(current, ()))
    return False
