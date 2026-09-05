from __future__ import annotations

from tests.utils.builders import analyze, make_context, make_source

from taut.domain.query_dependencies import SemanticInputChanges
from taut.policy.function_summary_dependencies import (
    build_function_summary_dependency_graph,
    function_summary_query,
)


def test_function_summary_dependencies_connect_callers_to_callees() -> None:
    context = make_context(
        analyze(
            make_source("app/leaf.py", "def leaf():\n    return None\n"),
            make_source(
                "app/caller.py",
                "from app.leaf import leaf\ndef caller():\n    leaf()\n",
            ),
        ),
        roles={"service": ("app/**",)},
    )
    graph = build_function_summary_dependency_graph(context, context.function_summary_state)
    leaf = function_summary_query(
        next(symbol for symbol in context.function_summaries if symbol.value.endswith(".leaf"))
    )
    caller = function_summary_query(
        next(symbol for symbol in context.function_summaries if symbol.value.endswith(".caller"))
    )
    leaf_definition = next(iter(graph.inputs_by_query[leaf]))

    assert graph.queries_by_query[caller] == frozenset({leaf})
    assert graph.affected_queries(SemanticInputChanges(frozenset({leaf_definition}))) == frozenset(
        {leaf, caller}
    )


def test_recursive_summary_dependency_graph_terminates() -> None:
    context = make_context(
        analyze(
            make_source(
                "app/service.py",
                "def first():\n    second()\n\ndef second():\n    first()\n",
            )
        ),
        roles={"service": ("app/**",)},
    )
    graph = build_function_summary_dependency_graph(context, context.function_summary_state)
    changed = next(
        semantic_input
        for inputs in graph.inputs_by_query.values()
        for semantic_input in inputs
        if semantic_input.family == "definition"
    )

    assert len(graph.affected_queries(SemanticInputChanges(frozenset({changed})))) == 2
