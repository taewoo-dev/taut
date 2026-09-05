from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from taut.domain.frozen import FrozenMap


@dataclass(frozen=True, order=True)
class SemanticInputKey:
    family: str
    identity: str

    def __post_init__(self) -> None:
        if not self.family.strip() or not self.identity.strip():
            raise ValueError("semantic input family and identity cannot be empty")


@dataclass(frozen=True, order=True)
class DerivedQueryKey:
    family: str
    identity: str
    behavior_version: int

    def __post_init__(self) -> None:
        if not self.family.strip() or not self.identity.strip():
            raise ValueError("derived query family and identity cannot be empty")
        if self.behavior_version < 1:
            raise ValueError("derived query behavior version must be positive")


@dataclass(frozen=True)
class SemanticInputChanges:
    changed: frozenset[SemanticInputKey]
    incompatible_schema: bool = False


@dataclass(frozen=True)
class ShadowInvalidation:
    changed_inputs: int
    proposed: frozenset[DerivedQueryKey]
    observed_changed: frozenset[DerivedQueryKey]
    missed: frozenset[DerivedQueryKey]

    @property
    def sound(self) -> bool:
        return not self.missed


@dataclass(frozen=True)
class QueryDependencyGraph:
    inputs_by_query: FrozenMap[DerivedQueryKey, frozenset[SemanticInputKey]]
    queries_by_query: FrozenMap[DerivedQueryKey, frozenset[DerivedQueryKey]]

    def affected_queries(self, changes: SemanticInputChanges) -> frozenset[DerivedQueryKey]:
        affected = {
            query
            for query, inputs in self.inputs_by_query.items()
            if not inputs.isdisjoint(changes.changed)
        }
        reverse: dict[DerivedQueryKey, set[DerivedQueryKey]] = {}
        for query, dependencies in self.queries_by_query.items():
            for dependency in dependencies:
                reverse.setdefault(dependency, set()).add(query)
        pending = list(affected)
        while pending:
            changed = pending.pop()
            for dependent in reverse.get(changed, ()):
                if dependent not in affected:
                    affected.add(dependent)
                    pending.append(dependent)
        return frozenset(affected)


class QueryDependencyRecorder:
    """Explicitly collect dependencies without process-global tracing state."""

    def __init__(self) -> None:
        self._inputs: dict[DerivedQueryKey, set[SemanticInputKey]] = {}
        self._queries: dict[DerivedQueryKey, set[DerivedQueryKey]] = {}

    def record(
        self,
        query: DerivedQueryKey,
        *,
        inputs: Iterable[SemanticInputKey] = (),
        queries: Iterable[DerivedQueryKey] = (),
    ) -> None:
        self._inputs.setdefault(query, set()).update(inputs)
        self._queries.setdefault(query, set()).update(queries)

    def freeze(self) -> QueryDependencyGraph:
        queries = frozenset(self._inputs) | frozenset(self._queries)
        return QueryDependencyGraph(
            FrozenMap((query, frozenset(self._inputs.get(query, ()))) for query in queries),
            FrozenMap((query, frozenset(self._queries.get(query, ()))) for query in queries),
        )
