from __future__ import annotations

from dataclasses import replace

from tests.utils.builders import analyze, make_source

from taut.incremental.query_dependencies import (
    DerivedQueryKey,
    QueryDependencyRecorder,
    SemanticInputChanges,
    SemanticInputKey,
    SemanticInputSnapshot,
)
from taut.incremental.semantic_digests import SemanticDigestIndex


def test_dependency_changes_propagate_through_derived_queries() -> None:
    changed_call = SemanticInputKey("call", "call-1")
    stable_call = SemanticInputKey("call", "call-2")
    leaf = DerivedQueryKey("function-summary", "app.leaf", 1)
    caller = DerivedQueryKey("function-summary", "app.caller", 1)
    unrelated = DerivedQueryKey("function-summary", "app.unrelated", 1)
    recorder = QueryDependencyRecorder()
    recorder.record(leaf, inputs=(changed_call,))
    recorder.record(caller, queries=(leaf,))
    recorder.record(unrelated, inputs=(stable_call,))

    affected = recorder.freeze().affected_queries(SemanticInputChanges(frozenset({changed_call})))

    assert affected == frozenset({leaf, caller})


def test_recursive_query_dependencies_terminate() -> None:
    changed = SemanticInputKey("definition", "definition-1")
    first = DerivedQueryKey("function-summary", "app.first", 1)
    second = DerivedQueryKey("function-summary", "app.second", 1)
    recorder = QueryDependencyRecorder()
    recorder.record(first, inputs=(changed,), queries=(second,))
    recorder.record(second, queries=(first,))

    assert recorder.freeze().affected_queries(
        SemanticInputChanges(frozenset({changed}))
    ) == frozenset({first, second})


def test_semantic_snapshot_detects_changed_added_and_removed_inputs() -> None:
    before = SemanticInputSnapshot.from_digests(
        SemanticDigestIndex.build(
            analyze(make_source("app/service.py", "def run():\n    first()\n")).modules.values()
        )
    )
    after = SemanticInputSnapshot.from_digests(
        SemanticDigestIndex.build(
            analyze(
                make_source("app/service.py", "def run(value: int):\n    second()\n")
            ).modules.values()
        )
    )

    changes = after.changes_from(before)

    assert not changes.incompatible_schema
    assert any(key.family == "definition" for key in changes.changed)
    assert any(key.family == "call" for key in changes.changed)


def test_schema_change_invalidates_every_input() -> None:
    current = SemanticInputSnapshot.from_digests(
        SemanticDigestIndex.build(
            analyze(make_source("app/service.py", "value = 1\n")).modules.values()
        )
    )
    prior = replace(current, schema_version=current.schema_version + 1)

    changes = current.changes_from(prior)

    assert changes.incompatible_schema
    assert changes.changed == frozenset(current.values)


def test_frozen_graph_is_deterministic() -> None:
    query = DerivedQueryKey("evaluation", "TX002:call", 1)
    first = SemanticInputKey("call", "first")
    second = SemanticInputKey("call", "second")
    left = QueryDependencyRecorder()
    right = QueryDependencyRecorder()
    left.record(query, inputs=(first, second))
    right.record(query, inputs=(second, first))

    assert left.freeze() == right.freeze()
