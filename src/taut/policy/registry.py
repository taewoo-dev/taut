from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from taut.domain.frozen import FrozenMap
from taut.domain.ids import RuleId
from taut.policy.rule import RuleDefinition


@dataclass(frozen=True)
class RuleRegistry:
    definitions: FrozenMap[RuleId, RuleDefinition]

    @classmethod
    def build(cls, definitions: Iterable[RuleDefinition]) -> RuleRegistry:
        values = tuple(definitions)
        identifiers = tuple(definition.id for definition in values)
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("duplicate rule id")
        for definition in values:
            if definition.id.value != definition.id.value.upper():
                raise ValueError("rule id must be uppercase")
        return cls(FrozenMap((definition.id, definition) for definition in values))

    def get(self, rule_id: RuleId) -> RuleDefinition:
        return self.definitions[rule_id]
