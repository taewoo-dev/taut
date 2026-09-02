"""Static feature and semantic-provider evidence used by onboarding."""

from __future__ import annotations

import ast
from pathlib import Path

from taut.configuration.assurance import BUILTIN_ASSURANCE_FEATURES


def detect_features(root: Path, paths: tuple[str, ...]) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {name: [] for name in BUILTIN_ASSURANCE_FEATURES}
    for path in paths:
        content = (root / path).read_text(errors="replace")
        lowered_parts = {part.lower() for part in Path(path).parts}

        def mark(name: str, condition: bool, evidence_path: str = path) -> None:
            if condition:
                values[name].append(evidence_path)

        mark("api", "fastapi" in content or "APIRouter" in content)
        mark("schema", "pydantic" in content or "BaseModel" in content)
        mark(
            "dto",
            _declares_dto(content) or bool({"dto", "dtos"}.intersection(lowered_parts)),
        )
        mark("snapshot", _declares_snapshot(path, content))
        mark("exception_registry", "Exception" in content or "ErrorCode" in content)
        mark("enum", "Enum" in content or "StrEnum" in content)
        mark("database", "sqlalchemy" in content or "tortoise" in content)
        mark(
            "transaction",
            "AsyncSession" in content
            or "in_transaction" in content
            or "@atomic" in content
            or ".commit(" in content,
        )
        mark(
            "external_calls",
            any(
                token in content for token in ("httpx", "requests", "openai", "anthropic", "boto3")
            ),
        )
        mark("security", "os.getenv" in content or "os.environ" in content)
        mark("tests", "tests" in lowered_parts or Path(path).name.startswith("test_"))
        mark("migrations", "migrations" in lowered_parts or "alembic" in lowered_parts)
        mark("scripts", "scripts" in lowered_parts)
    return values


def detect_providers(root: Path, paths: tuple[str, ...]) -> tuple[str, ...]:
    imported_roots: set[str] = set()
    for path in paths:
        try:
            tree = ast.parse((root / path).read_text(errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.partition(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.partition(".")[0])
    providers = ["taut.python-core"]
    for provider, modules in (
        ("taut.fastapi", ("fastapi", "starlette")),
        ("taut.pydantic", ("pydantic",)),
        ("taut.pytest", ("pytest",)),
        ("taut.sqlalchemy", ("sqlalchemy",)),
        ("taut.tortoise", ("tortoise",)),
    ):
        if imported_roots.intersection(modules):
            providers.append(provider)
    return tuple(providers)


def observed_response_mappers(root: Path, paths: tuple[str, ...]) -> tuple[str, ...]:
    names: set[str] = set()
    for path in paths:
        try:
            tree = ast.parse((root / path).read_text())
        except (OSError, UnicodeError, SyntaxError):
            continue
        for item in tree.body:
            if not isinstance(item, ast.ClassDef) or not item.name.endswith(
                ("Response", "ResponseModel")
            ):
                continue
            names.update(
                member.name
                for member in item.body
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                and member.name in {"from_internal", "from_result"}
            )
    return tuple(sorted(names))


def _declares_snapshot(path: str, content: str) -> bool:
    source_path = Path(path)
    if source_path.stem == "snapshot" or source_path.stem.endswith("_snapshot"):
        return True
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return False
    return any(
        isinstance(node, ast.ClassDef) and "Snapshot" in node.name for node in ast.walk(tree)
    )


def _declares_dto(content: str) -> bool:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return False
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or not node.name.endswith(("Data", "Result", "Row")):
            continue
        decorators = {
            _expression_name(item.func if isinstance(item, ast.Call) else item)
            for item in node.decorator_list
        }
        bases = {_expression_name(item) for item in node.bases}
        if decorators.intersection({"dataclass", "dataclasses.dataclass"}) or any(
            base.endswith(("BaseModel", "BaseDTO")) for base in bases
        ):
            return True
    return False


def _expression_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _expression_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""
