from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True, order=True)
class ProjectPath:
    value: str

    def __post_init__(self) -> None:
        normalized = self.value.replace("\\", "/")
        path = PurePosixPath(normalized)
        if not normalized or path.is_absolute() or ".." in path.parts:
            raise ValueError(f"project path must be a safe relative path: {self.value!r}")
        if normalized.startswith("./") or normalized != path.as_posix():
            raise ValueError(f"project path must already be normalized: {self.value!r}")
        object.__setattr__(self, "value", normalized)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, order=True)
class ConfigPath:
    """Config file path; absolute paths support read-only audits of another project."""

    value: str

    def __post_init__(self) -> None:
        normalized = self.value.replace("\\", "/")
        path = PurePosixPath(normalized)
        if not normalized or ".." in path.parts:
            raise ValueError(f"config path must not be empty or traverse parents: {self.value!r}")
        if normalized.startswith("./") or normalized != path.as_posix():
            raise ValueError(f"config path must already be normalized: {self.value!r}")
        object.__setattr__(self, "value", normalized)

    @property
    def is_absolute(self) -> bool:
        return PurePosixPath(self.value).is_absolute()

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, order=True)
class SourceRange:
    path: ProjectPath
    start_line: int
    start_column: int
    end_line: int
    end_column: int

    def __post_init__(self) -> None:
        coordinates = (self.start_line, self.start_column, self.end_line, self.end_column)
        if any(value < 0 for value in coordinates):
            raise ValueError("source positions are zero-based and cannot be negative")
        if (self.end_line, self.end_column) < (self.start_line, self.start_column):
            raise ValueError("source range end cannot be before its start")

    @property
    def display_line(self) -> int:
        return self.start_line + 1

    @property
    def display_column(self) -> int:
        return self.start_column + 1


@dataclass(frozen=True, order=True)
class ConfigLocation:
    path: ProjectPath | ConfigPath
    line: int | None = None
    column: int | None = None

    def __post_init__(self) -> None:
        if self.line is not None and self.line < 0:
            raise ValueError("config line cannot be negative")
        if self.column is not None and self.column < 0:
            raise ValueError("config column cannot be negative")
