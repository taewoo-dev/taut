from __future__ import annotations

import ast


def catches_import_error(handlers: list[ast.ExceptHandler]) -> bool:
    names = {"ImportError", "ModuleNotFoundError"}

    def catches(node: ast.expr | None) -> bool:
        if isinstance(node, ast.Name):
            return node.id in names
        if isinstance(node, ast.Tuple):
            return any(catches(item) for item in node.elts)
        return False

    return any(catches(handler.type) for handler in handlers)


def optional_import_nodes(tree: ast.Module) -> set[ast.Import | ast.ImportFrom]:
    result: set[ast.Import | ast.ImportFrom] = set()

    class OptionalImportVisitor(ast.NodeVisitor):
        def visit_Try(self, node: ast.Try) -> None:
            if catches_import_error(node.handlers):
                for statement in node.body:
                    self._visit_optional_body(statement)
            self.generic_visit(node)

        def visit_TryStar(self, node: ast.TryStar) -> None:
            if catches_import_error(node.handlers):
                for statement in node.body:
                    self._visit_optional_body(statement)
            self.generic_visit(node)

        def _visit_optional_body(self, node: ast.AST) -> None:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                result.add(node)
                return
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                return
            for child in ast.iter_child_nodes(node):
                self._visit_optional_body(child)

    OptionalImportVisitor().visit(tree)
    return result
