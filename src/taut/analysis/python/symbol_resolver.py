from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass

from taut.analysis.contracts import SourceInput
from taut.domain.facts import ResolutionState, SymbolRef
from taut.domain.ids import SymbolId
from taut.domain.location import SourceRange
from taut.domain.provenance import Provenance

_BUILTINS = frozenset(
    {
        "__import__",
        "bool",
        "dict",
        "enumerate",
        "float",
        "getattr",
        "int",
        "len",
        "list",
        "max",
        "min",
        "print",
        "range",
        "set",
        "str",
        "sum",
        "super",
        "tuple",
        "zip",
    }
)


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
class _Scope:
    symbol: SymbolId | None
    parent: SymbolId | None


class PythonSymbolResolver:
    def __init__(self, source: SourceInput) -> None:
        self.source = source
        self.current_scope: SymbolId | None = None
        self.scopes: dict[SymbolId | None, _Scope] = {None: _Scope(None, None)}
        self.bindings: dict[SymbolId | None, dict[str, SymbolId]] = defaultdict(dict)
        self.types: dict[SymbolId | None, dict[str, SymbolId]] = defaultdict(dict)
        self._locations: dict[ast.AST, SourceRange] = {}
        self._provenances: dict[ast.AST, Provenance] = {}
        self._written_names: dict[ast.AST, str] = {}
        self._resolutions: dict[ast.AST, SymbolRef] = {}

    def _prime_statements(self, statements: list[ast.stmt], scope: SymbolId | None) -> None:
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                symbol = self._child_symbol(scope, statement.name)
                self.bindings[scope][statement.name] = symbol
                self.scopes[symbol] = _Scope(symbol, scope)
                self._prime_statements(statement.body, symbol)
            elif isinstance(statement, ast.Import):
                for alias in statement.names:
                    self.bindings[scope][alias.asname or alias.name.split(".")[0]] = SymbolId(
                        alias.name if alias.asname else alias.name.split(".")[0]
                    )
            elif isinstance(statement, ast.ImportFrom):
                base = self._absolute_import_base(statement.module, statement.level)
                for alias in statement.names:
                    if alias.name != "*":
                        self.bindings[scope][alias.asname or alias.name] = SymbolId(
                            f"{base}.{alias.name}" if base else alias.name
                        )
            else:
                self._prime_nested_nodes(statement, scope)

    def _prime_nested_nodes(self, node: ast.AST, scope: SymbolId | None) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt):
                self._prime_statements([child], scope)
            else:
                self._prime_nested_nodes(child, scope)

    def _child_symbol(self, scope: SymbolId | None, name: str) -> SymbolId:
        return SymbolId(f"{scope.value if scope else self.source.module_id.value}.{name}")

    def _location(self, node: ast.AST) -> SourceRange:
        if node not in self._locations:
            self._locations[node] = node_range(self.source, node)
        return self._locations[node]

    def _provenance(self, node: ast.AST) -> Provenance:
        if node not in self._provenances:
            self._provenances[node] = Provenance(
                "python-ast", "1", self.source.content_hash, self._location(node)
            )
        return self._provenances[node]

    def _written_name(self, node: ast.AST) -> str:
        if node not in self._written_names:
            self._written_names[node] = written_name(node)
        return self._written_names[node]

    def _absolute_import_base(self, module: str | None, level: int) -> str:
        if level == 0:
            return module or ""
        parts = self.source.module_id.value.split(".")
        if not self.source.is_package:
            parts = parts[:-1]
        parts = parts[: max(0, len(parts) - level + 1)]
        if module:
            parts.extend(module.split("."))
        return ".".join(parts)

    def _scope_chain(self) -> list[SymbolId | None]:
        result: list[SymbolId | None] = []
        scope = self.current_scope
        while True:
            result.append(scope)
            if scope is None:
                return result
            scope = self.scopes[scope].parent

    def _lookup(self, name: str, *, type_only: bool = False) -> SymbolId | None:
        table = self.types if type_only else self.bindings
        for scope in self._scope_chain():
            if (value := table[scope].get(name)) is not None:
                return value
        return None

    def _resolve(self, node: ast.AST) -> SymbolRef:
        if node not in self._resolutions:
            self._resolutions[node] = self._resolve_uncached(node)
        return self._resolutions[node]

    def _resolve_uncached(self, node: ast.AST) -> SymbolRef:
        name = self._written_name(node)
        provenance = self._provenance(node)
        if isinstance(node, ast.Name):
            symbol = self._lookup(node.id) or (
                SymbolId(f"builtins.{node.id}") if node.id in _BUILTINS else None
            )
            state = ResolutionState.RESOLVED if symbol else ResolutionState.UNRESOLVED
            return SymbolRef(name, state, symbol, (), provenance)
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                typed = self._lookup(node.value.id, type_only=True)
                if typed is not None:
                    return SymbolRef(
                        name,
                        ResolutionState.RESOLVED,
                        SymbolId(f"{typed.value}.{node.attr}"),
                        (),
                        provenance,
                    )
            base = self._resolve(node.value)
            if base.state is ResolutionState.RESOLVED and base.symbol:
                return SymbolRef(
                    name,
                    ResolutionState.RESOLVED,
                    SymbolId(f"{base.symbol.value}.{node.attr}"),
                    (),
                    provenance,
                )
            return SymbolRef(name, base.state, None, base.candidates, provenance)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
        ):
            return SymbolRef(name, ResolutionState.DYNAMIC, None, (), provenance)
        return SymbolRef(name, ResolutionState.DYNAMIC, None, (), provenance)

    def _annotation_symbol(self, node: ast.expr | None) -> SymbolId | None:
        ref = self._resolve(node) if node is not None else None
        return ref.symbol if ref and ref.state is ResolutionState.RESOLVED else None
