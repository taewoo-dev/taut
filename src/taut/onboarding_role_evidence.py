from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class InitRoleEvidence:
    role: str
    kind: str
    value: str
    confidence: str

    def json_payload(self) -> dict[str, str]:
        return {
            "role": self.role,
            "kind": self.kind,
            "value": self.value,
            "confidence": self.confidence,
        }


def semantic_role_evidence(content: str) -> list[InitRoleEvidence]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".", 1)[0]] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"

    result: list[InitRoleEvidence] = []
    for descendant in ast.walk(tree):
        if isinstance(descendant, ast.ClassDef):
            for base in descendant.bases:
                symbol = _resolved_expression_name(base, aliases)
                if symbol == "tortoise.models.Model":
                    result.append(InitRoleEvidence("model", "inherits", symbol, "high"))
                elif symbol in {"pydantic.BaseModel", "pydantic.main.BaseModel"}:
                    result.append(InitRoleEvidence("schema", "inherits", symbol, "high"))
        elif isinstance(descendant, ast.Call):
            symbol = _resolved_expression_name(descendant.func, aliases)
            if symbol in {"fastapi.APIRouter", "fastapi.routing.APIRouter"}:
                result.append(InitRoleEvidence("router", "constructs", symbol, "high"))
    return result


def _resolved_expression_name(node: ast.expr, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _resolved_expression_name(node.value, aliases)
        return f"{parent}.{node.attr}" if parent is not None else None
    return None


def unique_role_evidence(values: list[InitRoleEvidence]) -> list[InitRoleEvidence]:
    seen: set[tuple[str, str, str, str]] = set()
    result: list[InitRoleEvidence] = []
    for item in values:
        key = (item.role, item.kind, item.value, item.confidence)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result
