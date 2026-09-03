"""Shared, deterministic project-path observations.

Onboarding, generated configuration, and strict assurance must agree about
which Python files belong to the project and which execution context owns a
file.  Keep those decisions here rather than reimplementing path heuristics in
each caller.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from taut.configuration.source_scope import IGNORED_DIRECTORY_NAMES


@dataclass(frozen=True, order=True)
class PathObservation:
    zone: str
    kind: str
    confidence: str
    evidence: str


def is_ignored_path(path: Path | PurePosixPath) -> bool:
    return any(part in IGNORED_DIRECTORY_NAMES for part in path.parts)


def observe_path(path: str) -> PathObservation:
    """Return one exclusive execution context for a project-relative path."""
    source = PurePosixPath(path)
    directories = tuple(part.lower() for part in source.parts[:-1])
    stem = source.stem.lower()
    if {"test", "tests"}.intersection(directories) or stem == "conftest":
        return PathObservation("test", "test_path", "high", path)
    if "migrations" in directories or "alembic" in directories:
        return PathObservation("migration", "migration_path", "high", path)
    if "scripts" in directories:
        return PathObservation("script", "script_path", "medium", path)
    return PathObservation("prod", "production_path", "high", path)


def python_files(root: Path) -> tuple[str, ...]:
    return tuple(
        sorted(
            path.relative_to(root).as_posix()
            for path in root.rglob("*.py")
            if path.is_file() and not is_ignored_path(path.relative_to(root))
        )
    )
