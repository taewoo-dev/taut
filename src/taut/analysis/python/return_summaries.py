from __future__ import annotations

import ast
from collections.abc import Callable

from taut.analysis.python.expression_summary import ExpressionSummarizer, Resolve, Write
from taut.domain.ids import SymbolId
from taut.domain.location import SourceRange


def return_values(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[ast.expr | None, ...]:
    returns: list[ast.expr | None] = []

    class ReturnVisitor(ast.NodeVisitor):
        def visit_Return(self, node: ast.Return) -> None:
            returns.append(node.value)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            del node

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            del node

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            del node

        def visit_Lambda(self, node: ast.Lambda) -> None:
            del node

    visitor = ReturnVisitor()
    for statement in node.body:
        visitor.visit(statement)
    return tuple(returns)


def returned_mapping_keys(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, ...] | None:
    returns = return_values(node)
    if not returns:
        return None
    key_sets: list[set[str]] = []
    for value in returns:
        if not isinstance(value, ast.Dict) or any(key is None for key in value.keys):
            return None
        keys = {
            key.value
            for key in value.keys
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }
        if len(keys) != len(value.keys):
            return None
        key_sets.append(keys)
    common = key_sets[0].copy()
    for keys in key_sets[1:]:
        common.intersection_update(keys)
    return tuple(sorted(common))


def resolved_return_symbols(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    resolve: Resolve,
    write: Write,
    location: Callable[[ast.AST], SourceRange],
) -> tuple[SymbolId, ...]:
    summarizer = ExpressionSummarizer(resolve, write, location)
    return tuple(
        sorted(
            {
                symbol
                for value in return_values(node)
                if value is not None
                for symbol in summarizer.symbols(value)
            }
        )
    )
