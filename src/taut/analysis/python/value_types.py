"""Resolve receiver values separately from function and module identities."""

from __future__ import annotations

import ast
from typing import Protocol

from taut.analysis.python.known_types import member_type, returned_type
from taut.domain.facts import ResolutionState, SymbolRef
from taut.domain.ids import SymbolId
from taut.domain.provenance import Provenance


class _ValueTypeHost(Protocol):
    class_symbols: set[SymbolId]
    variable_symbols: set[SymbolId]

    def _lookup(self, name: str, *, type_only: bool = False) -> SymbolId | None: ...
    def _resolve(self, node: ast.AST) -> SymbolRef: ...
    def _written_name(self, node: ast.AST) -> str: ...
    def _provenance(self, node: ast.AST) -> Provenance: ...
    def _symbol(self, value: str) -> SymbolId: ...
    def _value_type(self, node: ast.AST) -> SymbolId | None: ...
    def _is_value_receiver(self, node: ast.AST) -> bool: ...


class PythonValueTypesMixin(_ValueTypeHost):
    def _value_type(self, node: ast.AST) -> SymbolId | None:
        if isinstance(node, ast.Name):
            return self._lookup(node.id, type_only=True)
        if isinstance(node, ast.Attribute):
            owner = self._value_type(node.value)
            return member_type(owner, node.attr) if owner is not None else None
        awaited = isinstance(node, ast.Await)
        value = node.value if isinstance(node, ast.Await) else node
        if isinstance(value, ast.Call):
            callee = self._resolve(value.func)
            if callee.state is ResolutionState.RESOLVED and callee.symbol is not None:
                if not awaited and callee.symbol in self.class_symbols:
                    return callee.symbol
                return returned_type(callee.symbol, awaited=awaited)
        return None

    def _is_value_receiver(self, node: ast.AST) -> bool:
        if isinstance(node, (ast.Call, ast.Await)):
            return True
        if isinstance(node, ast.Attribute):
            return self._is_value_receiver(node.value)
        return isinstance(node, ast.Name) and self._value_type(node) is not None

    def _resolve_attribute(self, node: ast.Attribute) -> SymbolRef:
        name, provenance = self._written_name(node), self._provenance(node)
        typed = self._value_type(node.value)
        if typed is not None:
            return SymbolRef(
                name,
                ResolutionState.RESOLVED,
                self._symbol(f"{typed.value}.{node.attr}"),
                (),
                provenance,
            )
        # A member on a returned value needs value-type evidence. Appending its
        # name to the factory symbol fabricates calls such as Client.get.json.
        if self._is_value_receiver(node.value):
            return SymbolRef(name, ResolutionState.UNRESOLVED, None, (), provenance)
        base = self._resolve(node.value)
        if base.state is ResolutionState.RESOLVED and base.symbol is not None:
            if base.symbol in self.variable_symbols:
                return SymbolRef(name, ResolutionState.UNRESOLVED, None, (), provenance)
            return SymbolRef(
                name,
                ResolutionState.RESOLVED,
                self._symbol(f"{base.symbol.value}.{node.attr}"),
                (),
                provenance,
            )
        candidates = tuple(self._symbol(f"{item.value}.{node.attr}") for item in base.candidates)
        return SymbolRef(name, base.state, None, candidates, provenance)
