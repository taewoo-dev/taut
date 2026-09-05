from __future__ import annotations

from dataclasses import dataclass

from taut.domain.frozen import FrozenMap
from taut.domain.query_dependencies import (
    DerivedQueryKey,
    QueryDependencyGraph,
    ShadowInvalidation,
)
from taut.incremental.query_dependencies import SemanticInputSnapshot
from taut.incremental.semantic_digests import SemanticDigestIndex, semantic_digest
from taut.policy.context import PolicyContext
from taut.policy.function_summary_dependencies import (
    build_function_summary_dependency_graph,
    function_summary_query,
)


@dataclass(frozen=True)
class FunctionSummaryQuerySnapshot:
    inputs: SemanticInputSnapshot
    values: FrozenMap[DerivedQueryKey, str]
    dependencies: QueryDependencyGraph


def build_function_summary_query_snapshot(
    context: PolicyContext,
) -> FunctionSummaryQuerySnapshot:
    state = context.function_summary_state
    modules = tuple(context.model.module(module_id) for module_id in context.model.modules())
    inputs = SemanticInputSnapshot.from_digests(SemanticDigestIndex.build(modules))
    values = FrozenMap(
        (
            function_summary_query(symbol),
            semantic_digest("function-summary-value", summary),
        )
        for symbol, summary in state.summaries.items()
    )
    dependencies = build_function_summary_dependency_graph(context, state)
    return FunctionSummaryQuerySnapshot(inputs, values, dependencies)


def compare_function_summary_invalidation(
    prior: FunctionSummaryQuerySnapshot,
    current: FunctionSummaryQuerySnapshot,
) -> ShadowInvalidation:
    changes = current.inputs.changes_from(prior.inputs)
    dependencies = _combined_dependencies(prior.dependencies, current.dependencies)
    query_keys = frozenset(prior.values) | frozenset(current.values)
    topology_changes = frozenset(prior.values) ^ frozenset(current.values)
    proposed = dependencies.affected_queries(changes) | topology_changes
    observed = frozenset(
        query for query in query_keys if prior.values.get(query) != current.values.get(query)
    )
    return ShadowInvalidation(
        len(changes.changed), proposed, observed, observed.difference(proposed)
    )


def _combined_dependencies(
    prior: QueryDependencyGraph,
    current: QueryDependencyGraph,
) -> QueryDependencyGraph:
    queries = (
        frozenset(prior.inputs_by_query)
        | frozenset(current.inputs_by_query)
        | frozenset(prior.queries_by_query)
        | frozenset(current.queries_by_query)
    )
    return QueryDependencyGraph(
        FrozenMap(
            (
                query,
                prior.inputs_by_query.get(query, frozenset())
                | current.inputs_by_query.get(query, frozenset()),
            )
            for query in queries
        ),
        FrozenMap(
            (
                query,
                prior.queries_by_query.get(query, frozenset())
                | current.queries_by_query.get(query, frozenset()),
            )
            for query in queries
        ),
    )
