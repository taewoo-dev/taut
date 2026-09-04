"""Explicit workspace discovery without merging member analysis graphs."""

from __future__ import annotations

import os
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from taut.configuration.source_scope import IGNORED_DIRECTORY_NAMES
from taut.loading.errors import PolicyConfigError

WORKSPACE_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class WorkspaceMember:
    path: str
    root: Path


@dataclass(frozen=True)
class TautWorkspace:
    root: Path
    members: tuple[WorkspaceMember, ...]


def load_workspace(project_root: Path) -> TautWorkspace | None:
    """Load an explicitly declared Taut workspace from the root pyproject."""
    root = project_root.resolve()
    path = root / "pyproject.toml"
    if not path.is_file():
        return None
    document = _read_toml(path)
    tool = _mapping(document.get("tool"), "tool")
    raw_taut = tool.get("taut")
    if raw_taut is None:
        return None
    taut = _mapping(raw_taut, "tool.taut")
    raw_workspace = taut.get("workspace")
    if raw_workspace is None:
        return None
    project_keys = set(taut).difference({"workspace"})
    if project_keys:
        raise PolicyConfigError(
            "workspace root cannot also be a Taut project configuration; "
            f"move these keys into a member: {', '.join(sorted(project_keys))}"
        )
    workspace = _mapping(raw_workspace, "tool.taut.workspace")
    unknown = set(workspace).difference({"schema_version", "members"})
    if unknown:
        raise PolicyConfigError(f"unknown tool.taut.workspace keys: {', '.join(sorted(unknown))}")
    version = workspace.get("schema_version", WORKSPACE_SCHEMA_VERSION)
    if version != WORKSPACE_SCHEMA_VERSION:
        raise PolicyConfigError(f"workspace schema_version must be {WORKSPACE_SCHEMA_VERSION}")
    raw_members = workspace.get("members")
    if not isinstance(raw_members, list) or not raw_members:
        raise PolicyConfigError("tool.taut.workspace.members must be a non-empty array")
    member_values = cast(list[object], raw_members)
    if not all(isinstance(item, str) for item in member_values):
        raise PolicyConfigError("tool.taut.workspace.members must contain only paths")
    member_paths = cast(list[str], member_values)
    if len(member_paths) != len(set(member_paths)):
        raise PolicyConfigError("tool.taut.workspace.members must be unique")
    members = tuple(_workspace_member(root, item) for item in member_paths)
    _reject_overlapping_members(members)
    return TautWorkspace(root, tuple(sorted(members, key=lambda item: item.path)))


def discover_independent_projects(project_root: Path) -> tuple[str, ...]:
    """Find top-level nested Python projects when no root project metadata exists."""
    root = project_root.resolve()
    root_manifest = root / "pyproject.toml"
    if root_manifest.is_file():
        document = _read_toml(root_manifest)
        tool = _mapping(document.get("tool"), "tool")
        uv = _mapping(tool.get("uv"), "tool.uv")
        if "project" in document or "build-system" in document or "workspace" in uv:
            return ()
    candidates: list[Path] = []
    for current, directory_names, file_names in os.walk(root):
        directory_names[:] = sorted(
            name for name in directory_names if name not in IGNORED_DIRECTORY_NAMES
        )
        directory = Path(current)
        if directory != root and "pyproject.toml" in file_names:
            candidates.append(directory)
            directory_names[:] = []
    projects = tuple(path for path in candidates if _contains_python(path))
    return tuple(path.relative_to(root).as_posix() for path in sorted(projects))


def discover_workspace_projects(project_root: Path) -> tuple[str, ...]:
    """Discover Python project members that a workspace manifest must account for."""
    root = project_root.resolve()
    explicit: set[Path] = set()
    path = root / "pyproject.toml"
    if path.is_file():
        document = _read_toml(path)
        uv = _mapping(_mapping(document.get("tool"), "tool").get("uv"), "tool.uv")
        uv_workspace = _mapping(uv.get("workspace"), "tool.uv.workspace")
        members = _string_list(uv_workspace.get("members", []), "tool.uv.workspace.members")
        excludes = _string_list(uv_workspace.get("exclude", []), "tool.uv.workspace.exclude")
        for pattern in members:
            explicit.update(
                candidate.resolve()
                for candidate in root.glob(pattern)
                if candidate.is_dir()
                and candidate.resolve().is_relative_to(root)
                and not any(candidate.match(exclude) for exclude in excludes)
            )
    candidates = explicit or {
        directory
        for directory in _nested_pyproject_directories(root)
        if _contains_python(directory)
    }
    return tuple(
        sorted(
            candidate.relative_to(root).as_posix()
            for candidate in candidates
            if (candidate / "pyproject.toml").is_file() and _contains_python(candidate)
        )
    )


def unlisted_workspace_projects(workspace: TautWorkspace) -> tuple[str, ...]:
    declared = {member.path for member in workspace.members}
    return tuple(
        project
        for project in discover_workspace_projects(workspace.root)
        if project not in declared
    )


def workspace_toml(members: tuple[str, ...]) -> str:
    rendered = ", ".join(_toml_string(member) for member in members)
    return (
        "[tool.taut.workspace]\n"
        f"schema_version = {WORKSPACE_SCHEMA_VERSION}\n"
        f"members = [{rendered}]\n"
    )


def member_has_configuration(root: Path, member: str) -> bool:
    path = root / member / "pyproject.toml"
    if not path.is_file():
        return False
    document = _read_toml(path)
    tool = document.get("tool")
    return isinstance(tool, dict) and isinstance(cast(dict[object, object], tool).get("taut"), dict)


def write_workspace_manifest(root: Path, members: tuple[str, ...]) -> None:
    """Append a reviewed workspace declaration using an atomic replacement."""
    target = root.resolve() / "pyproject.toml"
    existing = target.read_text() if target.is_file() else ""
    if target.is_file():
        document = _read_toml(target)
        tool = _mapping(document.get("tool"), "tool")
        if "taut" in tool:
            raise PolicyConfigError("[tool.taut] already exists")
    content = existing.rstrip() + ("\n\n" if existing.strip() else "") + workspace_toml(members)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=target.parent, prefix=f".{target.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _workspace_member(root: Path, value: str) -> WorkspaceMember:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if not normalized or path.is_absolute() or ".." in path.parts or normalized != path.as_posix():
        raise PolicyConfigError(f"workspace member must be a safe normalized path: {value!r}")
    absolute = (root / normalized).resolve()
    if absolute == root or not absolute.is_relative_to(root):
        raise PolicyConfigError(f"workspace member escapes the workspace root: {value}")
    if not absolute.is_dir():
        raise PolicyConfigError(f"workspace member directory is missing: {value}")
    if not (absolute / "pyproject.toml").is_file():
        raise PolicyConfigError(f"workspace member has no pyproject.toml: {value}")
    return WorkspaceMember(normalized, absolute)


def _reject_overlapping_members(members: tuple[WorkspaceMember, ...]) -> None:
    for index, member in enumerate(members):
        for other in members[index + 1 :]:
            if member.root.is_relative_to(other.root) or other.root.is_relative_to(member.root):
                raise PolicyConfigError(
                    f"workspace members cannot overlap: {member.path}, {other.path}"
                )


def _contains_python(root: Path) -> bool:
    for _current, directory_names, file_names in os.walk(root):
        directory_names[:] = [
            name for name in directory_names if name not in IGNORED_DIRECTORY_NAMES
        ]
        if any(name.endswith((".py", ".pyi")) for name in file_names):
            return True
    return False


def _nested_pyproject_directories(root: Path) -> tuple[Path, ...]:
    values: list[Path] = []
    for current, directory_names, file_names in os.walk(root):
        directory_names[:] = sorted(
            name for name in directory_names if name not in IGNORED_DIRECTORY_NAMES
        )
        directory = Path(current)
        if directory != root and "pyproject.toml" in file_names:
            values.append(directory.resolve())
            directory_names[:] = []
    return tuple(sorted(values))


def _string_list(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise PolicyConfigError(f"{label} must contain only paths")
    strings: list[str] = []
    for item in cast(list[object], value):
        if not isinstance(item, str):
            raise PolicyConfigError(f"{label} must contain only paths")
        strings.append(item)
    return tuple(strings)


def _read_toml(path: Path) -> dict[str, object]:
    try:
        value: object = tomllib.loads(path.read_text())
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise PolicyConfigError(f"cannot read {path}: {error}") from error
    return _mapping(value, str(path))


def _mapping(value: object, label: str) -> dict[str, object]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PolicyConfigError(f"{label} must be a table")
    mapping = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in mapping):
        raise PolicyConfigError(f"{label} must be a table")
    return cast(dict[str, object], mapping)


def _toml_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'
