from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from typing import cast


class FrozenMap[K, V](Mapping[K, V]):
    """A small immutable mapping with deterministic iteration and hashing."""

    __slots__ = ("_hash", "_items", "_lookup")

    def __init__(
        self,
        values: Mapping[K, V] | Iterable[tuple[K, V]] = (),
    ) -> None:
        raw_items: Iterable[tuple[K, V]] = (
            cast(Mapping[K, V], values).items() if isinstance(values, Mapping) else values
        )
        items: list[tuple[K, V]] = list(raw_items)
        lookup: dict[K, V] = {}
        for key, value in items:
            if key in lookup:
                raise ValueError(f"duplicate key in FrozenMap: {key!r}")
            lookup[key] = value
        ordered = tuple(sorted(lookup.items(), key=lambda item: repr(item[0])))
        self._items: tuple[tuple[K, V], ...] = ordered
        self._lookup: dict[K, V] = lookup
        self._hash: int | None = None

    def __getitem__(self, key: K) -> V:
        return self._lookup[key]

    def __iter__(self) -> Iterator[K]:
        return (key for key, _ in self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __repr__(self) -> str:
        return f"FrozenMap({self._items!r})"

    def __hash__(self) -> int:
        if self._hash is None:
            self._hash = hash(self._items)
        return self._hash

    def items_tuple(self) -> tuple[tuple[K, V], ...]:
        return self._items
