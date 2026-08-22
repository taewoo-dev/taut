from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

_RULE_ID = re.compile(r"^[A-Z][A-Z0-9_]*[0-9]{3}$")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")


@lru_cache(maxsize=131_072)
def _is_dotted_identifier(value: str) -> bool:
    """Validate repeated decoded identifiers without rescanning every occurrence."""
    return (
        bool(value)
        and not value.startswith(".")
        and not value.endswith(".")
        and ".." not in value
        and value.replace(".", "_").isidentifier()
    )


@dataclass(frozen=True, order=True)
class ModuleId:
    value: str

    def __post_init__(self) -> None:
        if not _is_dotted_identifier(self.value):
            raise ValueError(f"invalid module id: {self.value!r}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, order=True)
class SymbolId:
    value: str

    def __post_init__(self) -> None:
        if not _is_dotted_identifier(self.value):
            raise ValueError(f"invalid symbol id: {self.value!r}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, order=True)
class RuleId:
    value: str

    def __post_init__(self) -> None:
        if not _RULE_ID.fullmatch(self.value):
            raise ValueError(f"invalid rule id: {self.value!r}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, order=True)
class FactId:
    value: str

    def __post_init__(self) -> None:
        if not _HEX_DIGEST.fullmatch(self.value):
            raise ValueError("fact id must be a 64-character lowercase hex digest")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, order=True)
class SnapshotId:
    value: str

    def __post_init__(self) -> None:
        if not _HEX_DIGEST.fullmatch(self.value):
            raise ValueError("snapshot id must be a 64-character lowercase hex digest")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, order=True)
class FindingFingerprint:
    value: str

    def __post_init__(self) -> None:
        if not _HEX_DIGEST.fullmatch(self.value):
            raise ValueError("finding fingerprint must be a 64-character lowercase hex digest")

    def __str__(self) -> str:
        return self.value
