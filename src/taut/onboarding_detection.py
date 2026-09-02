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
            "@dataclass" in content
            and any(suffix in content for suffix in ("Data", "Result", "Row")),
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
        ("taut.sqlalchemy", ("sqlalchemy",)),
        ("taut.tortoise", ("tortoise",)),
    ):
        if imported_roots.intersection(modules):
            providers.append(provider)
    return tuple(providers)


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
