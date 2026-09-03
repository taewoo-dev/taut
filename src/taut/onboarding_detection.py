"""Static feature and semantic-provider evidence used by onboarding."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from taut.configuration.assurance import BUILTIN_ASSURANCE_FEATURES
from taut.onboarding_contributors import onboarding_framework_specs
from taut.project_observation import observe_path

_EXTERNAL_MODULES = frozenset({"anthropic", "boto3", "httpx", "openai", "requests"})
_PYDANTIC_BASES = frozenset(
    {"pydantic.BaseModel", "pydantic.main.BaseModel", "pydantic.v1.BaseModel"}
)


@dataclass(frozen=True)
class PythonSourceObservation:
    path: str
    tree: ast.Module | None
    aliases: tuple[tuple[str, str], ...]
    imported_roots: frozenset[str]

    def resolve(self, node: ast.expr) -> str:
        return _resolved_expression_name(node, dict(self.aliases)) or ""


def observe_python_sources(
    root: Path, paths: tuple[str, ...]
) -> tuple[PythonSourceObservation, ...]:
    result: list[PythonSourceObservation] = []
    for path in paths:
        try:
            tree = ast.parse((root / path).read_text(errors="replace"))
        except (OSError, UnicodeError, SyntaxError):
            result.append(PythonSourceObservation(path, None, (), frozenset()))
            continue
        aliases: dict[str, str] = {}
        roots: set[str] = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                for item in node.names:
                    roots.add(item.name.partition(".")[0])
                    aliases[item.asname or item.name.partition(".")[0]] = item.name
            elif isinstance(node, ast.ImportFrom) and node.module:
                roots.add(node.module.partition(".")[0])
                for item in node.names:
                    aliases[item.asname or item.name] = f"{node.module}.{item.name}"
        result.append(
            PythonSourceObservation(path, tree, tuple(sorted(aliases.items())), frozenset(roots))
        )
    return tuple(result)


def detect_features(
    root: Path,
    paths: tuple[str, ...],
    observations: tuple[PythonSourceObservation, ...] | None = None,
) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {name: [] for name in BUILTIN_ASSURANCE_FEATURES}
    observed = observations or observe_python_sources(root, paths)
    for source in observed:
        path = source.path
        tree = source.tree
        path_observation = observe_path(path)
        lowered_parts = {part.lower() for part in Path(path).parts}

        def mark(name: str, condition: bool, evidence_path: str = path) -> None:
            if condition:
                values[name].append(evidence_path)

        classes = (
            tuple(node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)) if tree else ()
        )
        calls = tuple(node for node in ast.walk(tree) if isinstance(node, ast.Call)) if tree else ()
        resolved_bases = {source.resolve(base) for item in classes for base in item.bases}
        resolved_calls = {source.resolve(call.func) for call in calls}
        mark(
            "api",
            any(
                symbol in {"fastapi.APIRouter", "fastapi.routing.APIRouter"}
                for symbol in resolved_calls
            ),
        )
        mark("schema", bool(resolved_bases.intersection(_PYDANTIC_BASES)))
        mark(
            "dto",
            _declares_dto(tree, source) or bool({"dto", "dtos"}.intersection(lowered_parts)),
        )
        mark("snapshot", _declares_snapshot(path, classes))
        mark(
            "exception_registry",
            any(
                item.name == "ErrorCode"
                or any(source.resolve(base).endswith(("Exception", "Error")) for base in item.bases)
                for item in classes
            ),
        )
        mark(
            "enum",
            any(
                source.resolve(base).endswith((".Enum", ".StrEnum"))
                for item in classes
                for base in item.bases
            ),
        )
        mark("database", bool(source.imported_roots.intersection({"sqlalchemy", "tortoise"})))
        mark(
            "transaction",
            any(
                symbol.rsplit(".", 1)[-1]
                in {"atomic", "begin", "commit", "in_transaction", "rollback"}
                for symbol in resolved_calls
            ),
        )
        mark(
            "external_calls",
            any(symbol.partition(".")[0] in _EXTERNAL_MODULES for symbol in resolved_calls),
        )
        mark(
            "security",
            any(symbol in {"os.getenv", "os.environ.get"} for symbol in resolved_calls)
            or bool(tree and any(_is_os_environ_access(node, source) for node in ast.walk(tree))),
        )
        mark("tests", path_observation.zone == "test")
        mark("migrations", path_observation.zone == "migration")
        mark("scripts", path_observation.zone == "script")
    return values


def detect_providers(
    root: Path,
    paths: tuple[str, ...],
    observations: tuple[PythonSourceObservation, ...] | None = None,
) -> tuple[str, ...]:
    imported_roots: set[str] = set()
    for item in observations or observe_python_sources(root, paths):
        imported_roots.update(item.imported_roots)
    providers = ["taut.python-core"]
    for spec in onboarding_framework_specs():
        if imported_roots.intersection(spec.import_roots):
            providers.append(spec.provider_id)
    return tuple(providers)


def observed_response_mappers(
    root: Path,
    paths: tuple[str, ...],
    observations: tuple[PythonSourceObservation, ...] | None = None,
) -> tuple[str, ...]:
    names: set[str] = set()
    for source in observations or observe_python_sources(root, paths):
        tree = source.tree
        if tree is None:
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


def _declares_snapshot(path: str, classes: tuple[ast.ClassDef, ...]) -> bool:
    source_path = Path(path)
    if source_path.stem == "snapshot" or source_path.stem.endswith("_snapshot"):
        return True
    return any("Snapshot" in node.name for node in classes)


def _declares_dto(tree: ast.Module | None, source: PythonSourceObservation) -> bool:
    if tree is None:
        return False
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or not node.name.endswith(("Data", "Result", "Row")):
            continue
        decorators = {
            source.resolve(item.func if isinstance(item, ast.Call) else item)
            for item in node.decorator_list
        }
        bases = {source.resolve(item) for item in node.bases}
        if decorators.intersection({"dataclasses.dataclass"}) or any(
            base in _PYDANTIC_BASES or base.endswith("BaseDTO") for base in bases
        ):
            return True
    return False


def _resolved_expression_name(node: ast.expr, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        prefix = _resolved_expression_name(node.value, aliases)
        return f"{prefix}.{node.attr}" if prefix else None
    return None


def _is_os_environ_access(node: ast.AST, source: PythonSourceObservation) -> bool:
    return isinstance(node, ast.Subscript) and source.resolve(node.value) == "os.environ"
