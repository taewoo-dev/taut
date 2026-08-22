"""Deterministic one-pass indexes shared by framework providers."""

from __future__ import annotations

from collections.abc import Callable, Iterable


def grouped[K, V](items: Iterable[V], key: Callable[[V], K]) -> tuple[tuple[K, tuple[V, ...]], ...]:
    """Consume *items* once and return sorted immutable groups."""
    groups: dict[K, list[V]] = {}
    for item in items:
        groups.setdefault(key(item), []).append(item)
    return tuple((group_key, tuple(groups[group_key])) for group_key in sorted(groups, key=str))
