from __future__ import annotations

import ast
from collections.abc import Sequence

from taut.analysis.python.symbol_resolver import PythonSymbolResolver
from taut.analysis.python.syntax_context import SyntaxContextStack
from taut.domain.facts import GuardKind


class PythonControlFlowVisitor(PythonSymbolResolver, ast.NodeVisitor):
    _syntax: SyntaxContextStack

    def _visit_lambda_scope(self, node: ast.Lambda) -> None:
        for default in (*node.args.defaults, *(item for item in node.args.kw_defaults if item)):
            self.visit(default)
        previous = self.current_scope
        self.current_scope = self.node_scopes[node]
        self.visit(node.body)
        self.current_scope = previous

    def _visit_comprehension_scope(
        self, node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp
    ) -> None:
        first, *rest = node.generators
        self.visit(first.iter)
        previous = self.current_scope
        self.current_scope = self.node_scopes[node]
        self.visit(first.target)
        for condition in first.ifs:
            self.visit(condition)
        for generator in rest:
            self.visit(generator.iter)
            self.visit(generator.target)
            for condition in generator.ifs:
                self.visit(condition)
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)
        self.current_scope = previous

    def _visit_guarded_statements(
        self, statements: Sequence[ast.stmt], guard: GuardKind, type_checking: bool
    ) -> None:
        if type_checking:
            self._enter_type_checking()
        with self._syntax.occurrence(guard=guard):
            for statement in statements:
                self.visit(statement)
        if type_checking:
            self._leave_type_checking()

    def visit_If(self, node: ast.If) -> None:
        self._visit_if_flow(node, self.visit, self._visit_guarded_statements)

    def visit_For(self, node: ast.For) -> None:
        self._visit_loop_flow(node, self.visit, self._visit_guarded_statements)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._visit_loop_flow(node, self.visit, self._visit_guarded_statements)

    def visit_While(self, node: ast.While) -> None:
        self._visit_loop_flow(node, self.visit, self._visit_guarded_statements)

    def visit_Try(self, node: ast.Try) -> None:
        self._visit_try_flow(node, self.visit, self._visit_guarded_statements)

    def visit_TryStar(self, node: ast.TryStar) -> None:
        self._visit_try_flow(node, self.visit, self._visit_guarded_statements)

    def visit_Match(self, node: ast.Match) -> None:
        self._visit_match_flow(node, self.visit, self._visit_guarded_statements)
