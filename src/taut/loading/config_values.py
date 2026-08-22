from __future__ import annotations

from collections.abc import Iterable
from typing import cast

from taut.loading.errors import PolicyConfigError


def table(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise PolicyConfigError(f"{label} must be a table")
    unknown = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in unknown):
        raise PolicyConfigError(f"{label} must be a table")
    return cast(dict[str, object], value)


def table_list(value: object, label: str) -> tuple[dict[str, object], ...]:
    if not isinstance(value, list):
        raise PolicyConfigError(f"{label} must be an array of tables")
    return tuple(table(item, label) for item in cast(list[object], value))


def string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyConfigError(f"{label} must be a non-empty string")
    return value


def strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise PolicyConfigError(f"{label} must be an array of non-empty strings")
    items = cast(list[object], value)
    if not all(isinstance(item, str) and item.strip() for item in items):
        raise PolicyConfigError(f"{label} must be an array of non-empty strings")
    result = tuple(cast(list[str], items))
    ensure_unique(result, label)
    return result


def integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise PolicyConfigError(f"{label} must be an integer")
    return value


def reject_unknown(value: dict[str, object], allowed: frozenset[str], label: str) -> None:
    unknown = set(value).difference(allowed)
    if unknown:
        raise PolicyConfigError(f"unknown {label} keys: {', '.join(sorted(unknown))}")


def ensure_unique(values: Iterable[str], label: str) -> None:
    sequence = tuple(values)
    if len(sequence) != len(set(sequence)):
        raise PolicyConfigError(f"duplicate {label}")
