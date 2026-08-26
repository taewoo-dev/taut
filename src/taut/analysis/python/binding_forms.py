# pyright: reportPrivateUsage=false
from __future__ import annotations

import ast
from dataclasses import replace
from typing import Any, Protocol

from taut.analysis.contracts import SourceInput
from taut.domain.facts import (
    BindingFact,
    ExpressionSummary,
    FactKind,
    FieldFact,
    ReferenceFact,
    ResolutionState,
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
    fields: list[FieldFact]
    class_symbols: set[SymbolId]
    types: dict[SymbolId | None, dict[str, SymbolId]]
    _expression_summary: Any
    _reference_binding_ids: dict[FactId, FactId | None]
    _reference_candidate_binding_ids: dict[FactId, tuple[FactId, ...]]

    def _add_field(
        self,
        name: str,
        node: ast.AST,
        annotation: ExpressionSummary | None,
        value: ExpressionSummary | None,
        is_annotated: bool,
    ) -> None: ...

    def _declare_assignment(self, name: str, binding_id: FactId | None = None) -> None: ...
    def _resolved_binding_ids(self, node: ast.AST) -> tuple[FactId, ...]: ...
    def _binding_scope(self, name: str) -> SymbolId | None: ...
    def _child_symbol(self, scope: SymbolId | None, name: str) -> SymbolId: ...
    def _next_fact_id(self, kind: FactKind, normalized_subject: str) -> FactId: ...
    def _location(self, node: ast.AST) -> SourceRange: ...
    def _provenance(self, node: ast.AST) -> Provenance: ...
    def _syntax_context(self) -> SyntaxContext: ...
    def _resolve(self, node: ast.AST) -> SymbolRef: ...
    def _annotation_symbol(self, node: ast.expr | None) -> SymbolId | None: ...
    def generic_visit(self, node: ast.AST) -> Any: ...
    def _visit_lambda_scope(self, node: ast.Lambda) -> None: ...
    def _visit_comprehension_scope(
        self, node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp
    ) -> None: ...
    def _mark_target(self, target: ast.AST, kind: BindingKind) -> None: ...
    def _record_binding(self, name: str, node: ast.AST, kind: BindingKind) -> None: ...
    def visit(self, node: ast.AST) -> Any: ...


class PythonBindingFormsMixin:
    def visit_AnnAssign(self: _BindingHost, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name):
            annotation = self._annotation_symbol(node.annotation)
            if annotation is not None:
                self.types[self.current_scope][node.target.id] = annotation
            self._add_field(
                node.target.id,
                node,
                self._expression_summary(node.annotation),
                self._expression_summary(node.value) if node.value is not None else None,
                True,
            )
        self.generic_visit(node)

    def visit_Assign(self: _BindingHost, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._add_field(target.id, node, None, self._expression_summary(node.value), False)
        self.visit(node.value)
        inferred = None
        if isinstance(node.value, ast.Call):
            ref = self._resolve(node.value.func)
            if ref.state is ResolutionState.RESOLVED:
                inferred = ref.symbol
        if inferred is not None:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.types[self.current_scope][target.id] = inferred
        for target in node.targets:
            self.visit(target)

    def _add_field(
        self: _BindingHost,
        name: str,
        node: ast.AST,
        annotation: ExpressionSummary | None,
        value: ExpressionSummary | None,
        is_annotated: bool,
    ) -> None:
        if self.current_scope is not None and self.current_scope not in self.class_symbols:
            return
        symbol = self._child_symbol(self.current_scope, name)
        self.fields.append(
            FieldFact(
                id=self._next_fact_id(FactKind.FIELD, symbol.value),
                module_id=self.source.module_id,
                owner_symbol=self.current_scope,
                symbol_id=symbol,
                name=name,
                annotation=annotation,
                value=value,
                is_annotated=is_annotated,
                location=self._location(node),
                provenance=self._provenance(node),
                context=self._syntax_context(),
            )
        )

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
        binding_id = self._next_fact_id(FactKind.FIELD, f"binding:{kind}:{name}")
        self._declare_assignment(name, binding_id)
        scope = self._binding_scope(name)
        symbol = self._child_symbol(scope, name)
        self.binding_facts.append(
            BindingFact(
                id=binding_id,
                module_id=self.source.module_id,
                local_name=name,
                kind=kind,
                lexical_owner=scope,
                symbol_id=symbol,
                location=self._location(node),
                provenance=self._provenance(node),
                context=replace(self._syntax_context(), lexical_owner=scope),
            )
        )

    def _record_exception_binding(self: _BindingHost, node: ast.ExceptHandler) -> None:
        if node.name:
            self._record_binding(node.name, node, BindingKind.EXCEPTION)

    def visit_Name(self: _BindingHost, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            ref = self._resolve(node)
            reference_id = self._next_fact_id(
                FactKind.REFERENCE, ref.symbol.value if ref.symbol else ref.written_name
            )
            self.references.append(
                ReferenceFact(
                    id=reference_id,
                    module_id=self.source.module_id,
                    ref=ref,
                    enclosing_symbol=self.current_scope,
                    location=self._location(node),
                    provenance=self._provenance(node),
                    context=self._syntax_context(),
                )
            )
            candidate_binding_ids = self._resolved_binding_ids(node)
            self._reference_binding_ids[reference_id] = (
                candidate_binding_ids[0] if len(candidate_binding_ids) == 1 else None
            )
            self._reference_candidate_binding_ids[reference_id] = candidate_binding_ids
        elif isinstance(node.ctx, (ast.Store, ast.Del)):
            kind = self._binding_targets.get(node, BindingKind.ASSIGNMENT)
            binding_id = self._next_fact_id(FactKind.FIELD, f"binding:{kind}:{node.id}")
            self._declare_assignment(node.id, binding_id)
            scope = self._binding_scope(node.id)
            symbol = self._child_symbol(scope, node.id)
            self.binding_facts.append(
                BindingFact(
                    id=binding_id,
                    module_id=self.source.module_id,
                    local_name=node.id,
                    kind=kind,
                    lexical_owner=scope,
                    symbol_id=symbol,
                    location=self._location(node),
                    provenance=self._provenance(node),
                    context=replace(self._syntax_context(), lexical_owner=scope),
                )
            )

    def visit_Lambda(self: _BindingHost, node: ast.Lambda) -> None:
        scope = self.node_scopes[node]
        arguments = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
        if node.args.vararg is not None:
            arguments += (node.args.vararg,)
        if node.args.kwarg is not None:
            arguments += (node.args.kwarg,)
        for argument in arguments:
            symbol = self._child_symbol(scope, argument.arg)
            self.binding_facts.append(
                BindingFact(
                    id=self._next_fact_id(
                        FactKind.FIELD, f"parameter:{scope.value}:{argument.arg}"
                    ),
                    module_id=self.source.module_id,
                    local_name=argument.arg,
                    kind=BindingKind.PARAMETER,
                    lexical_owner=scope,
                    symbol_id=symbol,
                    location=self._location(argument),
                    provenance=self._provenance(argument),
                    context=replace(
                        self._syntax_context(), lexical_owner=scope, scope_kind=ScopeKind.FUNCTION
                    ),
                )
            )
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
