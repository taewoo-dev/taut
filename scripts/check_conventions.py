from __future__ import annotations

import ast
from pathlib import Path
from typing import cast

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src" / "taut"
TEST_ROOT = PROJECT_ROOT / "tests"
MAX_SOURCE_LINES = 500

ALLOWED_DEPENDENCIES: dict[str, frozenset[str]] = {
    "domain": frozenset({"domain"}),
    "analysis": frozenset({"domain", "analysis"}),
    "configuration": frozenset({"domain", "configuration"}),
    "policy": frozenset({"domain", "analysis", "configuration", "policy"}),
    "finding_processing": frozenset({"domain", "configuration", "finding_processing"}),
    "incremental": frozenset({"domain", "analysis", "policy", "incremental"}),
    "loading": frozenset({"domain", "analysis", "configuration", "loading"}),
    "reporting": frozenset({"domain", "reporting"}),
}


def python_files(root: Path) -> tuple[Path, ...]:
    return tuple(sorted(path for path in root.rglob("*.py") if "__pycache__" not in path.parts))


def parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(), filename=str(path))


def fail(messages: list[str]) -> None:
    if not messages:
        return
    joined = "\n".join(f"- {message}" for message in messages)
    raise SystemExit(f"Convention check failed:\n{joined}")


def check_file_size(paths: tuple[Path, ...]) -> list[str]:
    failures: list[str] = []
    for path in paths:
        line_count = len(path.read_text().splitlines())
        if line_count > MAX_SOURCE_LINES:
            relative = path.relative_to(PROJECT_ROOT)
            failures.append(f"{relative}: {line_count} lines exceeds {MAX_SOURCE_LINES}")
    return failures


def check_local_imports(paths: tuple[Path, ...]) -> list[str]:
    failures: list[str] = []
    for path in paths:
        tree = parse(path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for child in ast.walk(node):
                if isinstance(child, (ast.Import, ast.ImportFrom)):
                    relative = path.relative_to(PROJECT_ROOT)
                    failures.append(f"{relative}:{child.lineno}: function-local import")
    return failures


def imported_policy_parts(tree: ast.Module) -> tuple[tuple[str, int], ...]:
    imports: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        modules: list[str] = []
        line = 0
        if isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
            line = node.lineno
        elif isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
            line = node.lineno
        for module in modules:
            if module.startswith("taut."):
                parts = module.split(".")
                if len(parts) >= 2:
                    imports.append((parts[1], line))
    return tuple(imports)


def check_dependency_direction(paths: tuple[Path, ...]) -> list[str]:
    failures: list[str] = []
    for path in paths:
        relative = path.relative_to(SOURCE_ROOT)
        if len(relative.parts) < 2:
            continue
        owner = relative.parts[0]
        allowed = ALLOWED_DEPENDENCIES.get(owner)
        if allowed is None:
            continue
        for imported, line in imported_policy_parts(parse(path)):
            if imported not in allowed:
                shown = path.relative_to(PROJECT_ROOT)
                failures.append(f"{shown}:{line}: {owner} cannot depend on {imported}")
    return failures


def check_rule_purity(paths: tuple[Path, ...]) -> list[str]:
    failures: list[str] = []
    forbidden_modules = {"ast", "pathlib", "random", "socket", "subprocess", "time"}
    for path in paths:
        relative = path.relative_to(SOURCE_ROOT)
        if not relative.parts or relative.parts[0] != "policy" or "rules" not in relative.parts:
            continue
        tree = parse(path)
        for node in ast.walk(tree):
            modules: list[str] = []
            line = 0
            if isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
                line = node.lineno
            elif isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
                line = node.lineno
            for module in modules:
                root = module.split(".")[0]
                if root in forbidden_modules or module.startswith("taut.reporting"):
                    shown = path.relative_to(PROJECT_ROOT)
                    failures.append(f"{shown}:{line}: forbidden rule import {module}")
    return failures


def all_assignment_value(node: ast.stmt) -> ast.expr | None:
    match node:
        case ast.Assign(targets=targets, value=value) if any(
            isinstance(target, ast.Name) and target.id == "__all__" for target in targets
        ):
            return value
        case ast.AnnAssign(target=ast.Name(id="__all__"), value=value):
            return value
        case _:
            return None


def check_package_facades(paths: tuple[Path, ...]) -> list[str]:
    failures: list[str] = []
    root_init = SOURCE_ROOT / "__init__.py"
    for path in paths:
        if path.name != "__init__.py" or path == root_init:
            continue
        imported: set[str] = set()
        defined: set[str] = set()
        exported: list[str] | None = None
        for node in parse(path).body:
            if isinstance(node, ast.ImportFrom) and node.level > 0:
                if any(alias.name == "*" for alias in node.names):
                    failures.append(f"{path.relative_to(PROJECT_ROOT)}: wildcard export")
                imported.update(
                    local_name
                    for alias in node.names
                    if not (local_name := alias.asname or alias.name).startswith("_")
                )
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if not node.name.startswith("_"):
                    defined.add(node.name)
            value_node = all_assignment_value(node)
            if value_node is not None:
                try:
                    value = ast.literal_eval(value_node)
                except (ValueError, TypeError):
                    value = None
                if isinstance(value, list):
                    items = cast(list[object], value)
                    if all(isinstance(item, str) for item in items):
                        exported = cast(list[str], items)
        shown = path.relative_to(PROJECT_ROOT)
        if exported is None:
            failures.append(f"{shown}: package facade must define a literal __all__")
        elif len(exported) != len(set(exported)):
            failures.append(f"{shown}: duplicate name in __all__")
        elif set(exported) != imported | defined:
            failures.append(f"{shown}: __all__ must match public imports and definitions")
    return failures


def check_test_layout() -> list[str]:
    if not TEST_ROOT.exists():
        return []
    failures: list[str] = []
    for path in TEST_ROOT.glob("**/conftest.py"):
        if path.parent != TEST_ROOT:
            failures.append(f"{path.relative_to(PROJECT_ROOT)}: nested conftest.py is forbidden")
    allowed_roots = {"unit", "contract", "integration", "fixtures", "utils"}
    for path in TEST_ROOT.iterdir():
        if path.is_dir() and not path.name.startswith("__") and path.name not in allowed_roots:
            failures.append(f"tests/{path.name}: unknown top-level test group")
    return failures


def main() -> None:
    source_paths = python_files(SOURCE_ROOT)
    test_paths = python_files(TEST_ROOT) if TEST_ROOT.exists() else ()
    script_paths = python_files(PROJECT_ROOT / "scripts")
    failures = [
        *check_file_size(source_paths),
        *check_local_imports((*source_paths, *test_paths, *script_paths)),
        *check_dependency_direction(source_paths),
        *check_rule_purity(source_paths),
        *check_package_facades(source_paths),
        *check_test_layout(),
    ]
    fail(failures)
    print("Convention checks passed")


if __name__ == "__main__":
    main()
