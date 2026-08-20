# pyright: reportPrivateUsage=false
from __future__ import annotations

import ast
from dataclasses import replace
from typing import Any, Protocol

from taut.analysis.contracts import SourceInput
from taut.domain.facts import (
    BindingFact,
    FactKind,
    GuardKind,
    ReferenceFact,
    ScopeKind,
    SymbolRef,
    SyntaxContext,
)
from taut.domain.ids import FactId, SymbolId
from taut.domain.location import SourceRange
from taut.domain.provenance import Provenance
from taut.domain.relations import BindingKind


class _BindingHost(Protocol):
    source: SourceInput
    current_scope: SymbolId | None
    node_scopes: dict[ast.AST, SymbolId]
    _binding_targets: dict[ast.AST, BindingKind]
    binding_facts: list[BindingFact]
    references: list[ReferenceFact]

    def _declare_assignment(self, name: str) -> None: ...
    def _binding_scope(self, name: str) -> SymbolId | None: ...
    def _child_symbol(self, scope: SymbolId | None, name: str) -> SymbolId: ...
    def _fact_id(self, kind: FactKind, normalized_subject: str) -> FactId: ...
    def _location(self, node: ast.AST) -> SourceRange: ...
    def _provenance(self, node: ast.AST) -> Provenance: ...
    def _syntax_context(self) -> SyntaxContext: ...
    def _contextual_ref(self, ref: SymbolRef, guard: GuardKind) -> SymbolRef: ...
    def _resolve(self, node: ast.AST) -> SymbolRef: ...
    def _visit_lambda_scope(self, node: ast.Lambda) -> None: ...
    def _visit_comprehension_scope(
        self, node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp
    ) -> None: ...
    def _mark_target(self, target: ast.AST, kind: BindingKind) -> None: ...
    def _record_binding(self, name: str, node: ast.AST, kind: BindingKind) -> None: ...
    def visit(self, node: ast.AST) -> Any: ...


class PythonBindingFormsMixin:
    def _index_binding_targets(self: _BindingHost, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else (node.target,)
                for target in targets:
                    self._mark_target(target, BindingKind.ASSIGNMENT)
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                self._mark_target(node.target, BindingKind.LOOP)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        self._mark_target(item.optional_vars, BindingKind.WITH_ITEM)
            elif isinstance(node, ast.NamedExpr):
                self._mark_target(node.target, BindingKind.WALRUS)
            elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                for generator in node.generators:
                    self._mark_target(generator.target, BindingKind.COMPREHENSION)

    def _mark_target(self: _BindingHost, target: ast.AST, kind: BindingKind) -> None:
        for child in ast.walk(target):
            if isinstance(child, ast.Name):
                self._binding_targets[child] = kind

    def _record_binding(self: _BindingHost, name: str, node: ast.AST, kind: BindingKind) -> None:
        self._declare_assignment(name)
        scope = self._binding_scope(name)
        symbol = self._child_symbol(scope, name)
        self.binding_facts.append(BindingFact(
            id=self._fact_id(FactKind.FIELD, f"binding:{kind}:{name}"),
            module_id=self.source.module_id,
            local_name=name, kind=kind, lexical_owner=scope, symbol_id=symbol,
            location=self._location(node), provenance=self._provenance(node),
            context=replace(self._syntax_context(), lexical_owner=scope),
        ))

    def _record_exception_binding(self: _BindingHost, node: ast.ExceptHandler) -> None:
        if node.name:
            self._record_binding(node.name, node, BindingKind.EXCEPTION)

    def visit_Name(self: _BindingHost, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            ref = self._contextual_ref(self._resolve(node), self._syntax_context().guard)
            self.references.append(ReferenceFact(
                id=self._fact_id(
                    FactKind.REFERENCE, ref.symbol.value if ref.symbol else ref.written_name
                ),
                module_id=self.source.module_id, ref=ref, enclosing_symbol=self.current_scope,
                location=self._location(node), provenance=self._provenance(node),
                context=self._syntax_context(),
            ))
        elif isinstance(node.ctx, (ast.Store, ast.Del)):
            kind = self._binding_targets.get(node, BindingKind.ASSIGNMENT)
            self._declare_assignment(node.id)
            scope = self._binding_scope(node.id)
            symbol = self._child_symbol(scope, node.id)
            self.binding_facts.append(BindingFact(
                id=self._fact_id(FactKind.FIELD, f"binding:{kind}:{node.id}"),
                module_id=self.source.module_id,
                local_name=node.id, kind=kind, lexical_owner=scope, symbol_id=symbol,
                location=self._location(node), provenance=self._provenance(node),
                context=replace(self._syntax_context(), lexical_owner=scope),
            ))

    def visit_Lambda(self: _BindingHost, node: ast.Lambda) -> None:
        scope = self.node_scopes[node]
        arguments = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
        if node.args.vararg is not None:
            arguments += (node.args.vararg,)
        if node.args.kwarg is not None:
            arguments += (node.args.kwarg,)
        for argument in arguments:
            symbol = self._child_symbol(scope, argument.arg)
            self.binding_facts.append(BindingFact(
                id=self._fact_id(FactKind.FIELD, f"parameter:{scope.value}:{argument.arg}"),
                module_id=self.source.module_id, local_name=argument.arg,
                kind=BindingKind.PARAMETER,
                lexical_owner=scope, symbol_id=symbol, location=self._location(argument),
                provenance=self._provenance(argument),
                context=replace(
                    self._syntax_context(), lexical_owner=scope, scope_kind=ScopeKind.FUNCTION
                ),
            ))
        self._visit_lambda_scope(node)

    def _visit_comprehension(
        self: _BindingHost,
        node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp,
    ) -> None:
        self._visit_comprehension_scope(node)

    visit_ListComp = _visit_comprehension
    visit_SetComp = _visit_comprehension
    visit_DictComp = _visit_comprehension
    visit_GeneratorExp = _visit_comprehension

    def visit_MatchAs(self: _BindingHost, node: ast.MatchAs) -> None:
        if node.name:
            self._record_binding(node.name, node, BindingKind.PATTERN)
        if node.pattern is not None:
            self.visit(node.pattern)

    def visit_MatchStar(self: _BindingHost, node: ast.MatchStar) -> None:
        if node.name:
            self._record_binding(node.name, node, BindingKind.PATTERN)

    def visit_MatchMapping(self: _BindingHost, node: ast.MatchMapping) -> None:
        if node.rest:
            self._record_binding(node.rest, node, BindingKind.PATTERN)
        for key in node.keys:
            self.visit(key)
        for pattern in node.patterns:
            self.visit(pattern)
