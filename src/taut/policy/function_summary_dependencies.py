from __future__ import annotations

from taut.domain.ids import SymbolId
from taut.domain.query_dependencies import (
    DerivedQueryKey,
    QueryDependencyGraph,
    QueryDependencyRecorder,
    SemanticInputKey,
)
from taut.policy.function_summaries import FunctionSummaryContext, FunctionSummaryState

FUNCTION_SUMMARY_QUERY_VERSION = 1


def function_summary_query(symbol: SymbolId) -> DerivedQueryKey:
    return DerivedQueryKey("function-summary", symbol.value, FUNCTION_SUMMARY_QUERY_VERSION)


def build_function_summary_dependency_graph(
    context: FunctionSummaryContext,
    state: FunctionSummaryState,
) -> QueryDependencyGraph:
    """Build summary dependencies on demand for shadow or incremental query runs."""
    model = context.model
    recorder = QueryDependencyRecorder()
    for module_id in model.modules():
        module = model.module(module_id)
        calls_by_owner = {
            function.symbol_id: tuple(
                call for call in module.calls if call.enclosing_symbol == function.symbol_id
            )
            for function in module.functions
        }
        for function in module.functions:
            symbol = model.canonical_symbol(function.symbol_id)
            if symbol not in state.summaries:
                continue
            recorder.record(
                function_summary_query(symbol),
                inputs=(
                    SemanticInputKey("module-interface", module_id.value),
                    SemanticInputKey("definition", function.id.value),
                    *(
                        SemanticInputKey("call", call.id.value)
                        for call in calls_by_owner[function.symbol_id]
                    ),
                ),
                queries=(function_summary_query(callee) for callee in state.graph.get(symbol, ())),
            )
    return recorder.freeze()
