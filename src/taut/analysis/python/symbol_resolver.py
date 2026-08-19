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

    def _prime_statements(
        self,
        statements: list[ast.stmt],
        scope: SymbolId | None,
    ) -> None:
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                symbol = self._child_symbol(scope, statement.name)
                self.bindings[scope][statement.name] = symbol
                self.scopes[symbol] = _Scope(symbol, scope)
                self._prime_statements(statement.body, symbol)
            elif isinstance(statement, ast.Import):
                for alias in statement.names:
                    local_name = alias.asname or alias.name.split(".")[0]
                    target = alias.name if alias.asname else alias.name.split(".")[0]
                    self.bindings[scope][local_name] = SymbolId(target)
            elif isinstance(statement, ast.ImportFrom):
                base = self._absolute_import_base(statement.module, statement.level)
                for alias in statement.names:
                    if alias.name == "*":
                        continue
                    local_name = alias.asname or alias.name
                    target = f"{base}.{alias.name}" if base else alias.name
                    self.bindings[scope][local_name] = SymbolId(target)
            else:
                self._prime_nested_nodes(statement, scope)

    def _prime_nested_nodes(self, node: ast.AST, scope: SymbolId | None) -> None:
        """Find definitions hidden inside control-flow blocks in the same scope."""
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt):
                self._prime_statements([child], scope)
            else:
                self._prime_nested_nodes(child, scope)

    def _child_symbol(self, scope: SymbolId | None, name: str) -> SymbolId:
        prefix = scope.value if scope else self.source.module_id.value
        return SymbolId(f"{prefix}.{name}")

    def _provenance(self, node: ast.AST) -> Provenance:
        cached = self._provenances.get(node)
        if cached is not None:
            return cached
        provenance = Provenance(
            provider="python-ast",
            provider_version="1",
            source_hash=self.source.content_hash,
            location=self._location(node),
        )
        self._provenances[node] = provenance
        return provenance

    def _location(self, node: ast.AST) -> SourceRange:
        cached = self._locations.get(node)
        if cached is not None:
            return cached
        location = node_range(self.source, node)
        self._locations[node] = location
        return location

    def _written_name(self, node: ast.AST) -> str:
        cached = self._written_names.get(node)
        if cached is not None:
            return cached
        value = written_name(node)
        self._written_names[node] = value
        return value

    def _absolute_import_base(self, module: str | None, level: int) -> str:
        if level == 0:
            return module or ""
        package_parts = self.source.module_id.value.split(".")
        if not self.source.is_package:
            package_parts = package_parts[:-1]
        up = level - 1
        if up > len(package_parts):
            return module or ""
        base_parts = package_parts[: len(package_parts) - up]
        if module:
            base_parts.extend(module.split("."))
        return ".".join(base_parts)

    def _scope_chain(self) -> list[SymbolId | None]:
        result: list[SymbolId | None] = []
        scope = self.current_scope
        while True:
            result.append(scope)
            if scope is None:
                break
            scope = self.scopes[scope].parent
        return result

    def _lookup(self, name: str, *, type_only: bool = False) -> SymbolId | None:
        table = self.types if type_only else self.bindings
        for scope in self._scope_chain():
            value = table[scope].get(name)
            if value is not None:
                return value
        return None

    def _resolve(self, node: ast.AST) -> SymbolRef:
        cached = self._resolutions.get(node)
        if cached is not None:
            return cached
        resolved = self._resolve_uncached(node)
        self._resolutions[node] = resolved
        return resolved

    def _resolve_uncached(self, node: ast.AST) -> SymbolRef:
        written = self._written_name(node)
        provenance = self._provenance(node)
        if isinstance(node, ast.Name):
            symbol = self._lookup(node.id)
            if symbol is None and node.id in _BUILTINS:
                symbol = SymbolId(f"builtins.{node.id}")
            if symbol is not None:
                return SymbolRef(written, ResolutionState.RESOLVED, symbol, (), provenance)
            return SymbolRef(written, ResolutionState.UNRESOLVED, None, (), provenance)
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                typed = self._lookup(node.value.id, type_only=True)
                if typed is not None:
                    symbol = SymbolId(f"{typed.value}.{node.attr}")
                    return SymbolRef(written, ResolutionState.RESOLVED, symbol, (), provenance)
            base = self._resolve(node.value)
            if base.state is ResolutionState.RESOLVED and base.symbol is not None:
                symbol = SymbolId(f"{base.symbol.value}.{node.attr}")
                return SymbolRef(written, ResolutionState.RESOLVED, symbol, (), provenance)
            return SymbolRef(written, base.state, None, base.candidates, provenance)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
        ):
            return SymbolRef(written, ResolutionState.DYNAMIC, None, (), provenance)
        return SymbolRef(written, ResolutionState.DYNAMIC, None, (), provenance)

    def _annotation_symbol(self, node: ast.expr | None) -> SymbolId | None:
        if node is None:
            return None
        ref = self._resolve(node)
        return ref.symbol if ref.state is ResolutionState.RESOLVED else None
