"""Canonical Python module identity and import resolution primitives."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from pathlib import Path, PurePath

from taut.domain.ids import ModuleId


def most_specific_source_root[PathT: PurePath](
    path: PathT, roots: tuple[PathT, ...]
) -> PathT | None:
    matching = tuple(root for root in roots if path.is_relative_to(root))
    if not matching:
        return None
    return max(matching, key=lambda root: len(root.parts))


def module_identity(relative_path: Path) -> tuple[ModuleId, bool]:
    parts = list(relative_path.parts)
    is_package = parts[-1] == "__init__.py"
    if is_package:
        parts = parts[:-1]
    else:
        parts[-1] = relative_path.stem
    if not parts:
        raise ValueError("source root __init__.py has no logical module name")
    return ModuleId(".".join(_module_part(part) for part in parts)), is_package


def absolute_import_base(
    module_id: ModuleId,
    is_package: bool,
    imported_module: str | None,
    relative_level: int,
) -> str:
    if relative_level == 0:
        return imported_module or ""
    parts = module_id.value.split(".")
    if not is_package:
        parts = parts[:-1]
    parts = parts[: max(0, len(parts) - relative_level + 1)]
    if imported_module:
        parts.extend(imported_module.split("."))
    return ".".join(parts)


def resolve_internal_import(
    imported_name: str,
    imported_module_name: str,
    modules_by_name: Mapping[str, ModuleId],
) -> ModuleId | None:
    for candidate in (imported_name, imported_module_name):
        current = candidate
        while current:
            module_id = modules_by_name.get(current)
            if module_id is not None:
                return module_id
            current = current.rpartition(".")[0]
    return None


def _module_part(value: str) -> str:
    if value.isidentifier():
        return value
    readable = re.sub(r"\W", "_", value)
    if not readable or not readable.isidentifier():
        readable = "source"
    digest = hashlib.sha256(value.encode()).hexdigest()[:8]
    return f"{readable}_{digest}"
