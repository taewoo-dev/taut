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
