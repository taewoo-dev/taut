from __future__ import annotations

from dataclasses import dataclass

from taut.domain.frozen import FrozenMap
from taut.domain.query_dependencies import (
    DerivedQueryKey,
    QueryDependencyGraph,
    QueryDependencyRecorder,
    SemanticInputChanges,
    SemanticInputKey,
)
from taut.incremental.semantic_digests import SEMANTIC_DIGEST_SCHEMA, SemanticDigestIndex


@dataclass(frozen=True)
class SemanticInputSnapshot:
    schema_version: int
    values: FrozenMap[SemanticInputKey, str]

    @classmethod
    def from_digests(cls, digests: SemanticDigestIndex) -> SemanticInputSnapshot:
        values = (
            *(
                (SemanticInputKey("module-interface", key.value), value)
                for key, value in digests.module_interfaces.items()
            ),
            *(
                (SemanticInputKey("definition", key.value), value)
                for key, value in digests.definitions.items()
            ),
            *((SemanticInputKey("call", key.value), value) for key, value in digests.calls.items()),
            *(
                (SemanticInputKey("binding", key.value), value)
                for key, value in digests.bindings.items()
            ),
        )
        return cls(digests.schema_version, FrozenMap(values))

    def changes_from(self, prior: SemanticInputSnapshot) -> SemanticInputChanges:
        keys = frozenset(self.values) | frozenset(prior.values)
        incompatible = self.schema_version != prior.schema_version
        changed = (
            keys
            if incompatible
            else frozenset(key for key in keys if self.values.get(key) != prior.values.get(key))
        )
        return SemanticInputChanges(changed, incompatible)


def empty_semantic_input_snapshot() -> SemanticInputSnapshot:
    return SemanticInputSnapshot(SEMANTIC_DIGEST_SCHEMA, FrozenMap[SemanticInputKey, str]())


__all__ = [
    "DerivedQueryKey",
    "QueryDependencyGraph",
    "QueryDependencyRecorder",
    "SemanticInputChanges",
    "SemanticInputKey",
    "SemanticInputSnapshot",
    "empty_semantic_input_snapshot",
]
