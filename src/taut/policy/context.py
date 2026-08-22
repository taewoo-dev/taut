from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from functools import cached_property
from types import MappingProxyType

from taut.analysis.semantic_model import SemanticModel
from taut.configuration.catalog import (
    EffectCatalog,
    EffectResolution,
    EffectResolver,
)
from taut.configuration.effective_policy import EffectivePolicy
from taut.configuration.manifest import ClassificationIndex
from taut.domain.facts import CallFact
from taut.domain.ids import FactId, SymbolId
from taut.policy.indexes import PolicyIndexes


@dataclass(frozen=True)
class PolicyContext:
    model: SemanticModel
    classification: ClassificationIndex
    effects: EffectResolver
    catalog: EffectCatalog
    policy: EffectivePolicy

    @cached_property
    def indexes(self) -> PolicyIndexes:
        return PolicyIndexes.build(self.model, self.classification, self.policy)

    @cached_property
    def effect_resolutions(self) -> Mapping[FactId, EffectResolution]:
        """Resolve each call at most once during one policy run."""
        resolved = {
            call.id: self.effects.resolve(call, self.catalog)
            for module_id in self.model.modules()
            for call in self.model.module(module_id).calls
        }
        return MappingProxyType(resolved)

    def effect_of(self, call: CallFact) -> EffectResolution:
        return self.effect_resolutions[call.id]

    def symbol_in(self, symbol: SymbolId | None, candidates: frozenset[SymbolId]) -> bool:
        if symbol is None:
            return False
        canonical = self.model.canonical_symbol(symbol)
        return any(self.model.canonical_symbol(candidate) == canonical for candidate in candidates)
