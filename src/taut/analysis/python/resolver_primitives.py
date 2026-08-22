from __future__ import annotations

import ast
from dataclasses import dataclass

from taut.analysis.contracts import SourceInput
from taut.domain.ids import SymbolId
from taut.domain.location import SourceRange


def node_range(source: SourceInput, node: ast.AST) -> SourceRange:
    start_line = max(getattr(node, "lineno", 1) - 1, 0)
    start_column = max(getattr(node, "col_offset", 0), 0)
    end_line = max(getattr(node, "end_lineno", start_line + 1) - 1, start_line)
    end_column = max(getattr(node, "end_col_offset", start_column), 0)
    return SourceRange(source.path, start_line, start_column, end_line, end_column)


def written_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{written_name(node.value)}.{node.attr}"
    try:
        return ast.unparse(node)
    except (ValueError, TypeError):
        return node.__class__.__name__


@dataclass(frozen=True)
class Scope:
    symbol: SymbolId | None
    parent: SymbolId | None
    kind: str
