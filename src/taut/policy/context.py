from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from functools import cached_property
from types import MappingProxyType

from taut.analysis.framework.tortoise_facts import TortoiseQueryFact, TortoiseTransactionFact
from taut.analysis.semantic_model import SemanticModel
from taut.configuration.catalog import (
    AccessPath,
    CatalogEntry,
    Effect,
    EffectCatalog,
    EffectResolution,
    EffectResolutionState,
    EffectResolver,
)
from taut.configuration.effective_policy import EffectivePolicy, PolicyApproval
from taut.configuration.manifest import ClassificationIndex
from taut.domain.facts import CallFact, ResolutionState
from taut.domain.frozen import FrozenMap
from taut.domain.ids import FactId, ModuleId, RuleId, SymbolId
from taut.policy.indexes import PolicyIndexes
from taut.policy.symbol_contracts import SymbolContractIndex


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
    def symbol_contracts(self) -> SymbolContractIndex:
        return SymbolContractIndex.build(self.model, self.classification, self.policy)

    @cached_property
    def effect_resolutions(self) -> Mapping[FactId, EffectResolution]:
        """Resolve each call at most once during one policy run."""
        resolved = {
            call.id: self.effects.resolve(self._canonical_call(call), self.canonical_catalog)
            for module_id in self.model.modules()
            for call in self.model.module(module_id).calls
        }
        return MappingProxyType(resolved)

    def effect_of(self, call: CallFact) -> EffectResolution:
        resolution = self.effect_resolutions[call.id]
        transaction = self.tortoise_transactions.get(call.id)
        if (
            resolution.state is EffectResolutionState.NO_MATCH
            and transaction is not None
            and transaction.confidence is ResolutionState.RESOLVED
            and transaction.operation in {"commit", "rollback"}
        ):
            effect = Effect.TX_COMMIT if transaction.operation == "commit" else Effect.TX_ROLLBACK
            return EffectResolution(
                EffectResolutionState.MATCHED,
                frozenset({effect}),
                AccessPath.DIRECT,
                None,
            )
        return resolution

    @cached_property
    def tortoise_queries(self) -> Mapping[FactId, TortoiseQueryFact]:
        """Index Tortoise query facts without coupling boundary rules to fact classes."""
        return MappingProxyType(
            {
                fact.call.id: fact
                for fact in self.model.capability_values("taut.tortoise.queries@1")
                if isinstance(fact, TortoiseQueryFact)
            }
        )

    @cached_property
    def tortoise_transactions(self) -> Mapping[FactId, TortoiseTransactionFact]:
        return MappingProxyType(
            {
                fact.call.id: fact
                for fact in self.model.capability_values("taut.tortoise.transactions@1")
                if isinstance(fact, TortoiseTransactionFact)
            }
        )

    def _canonical_call(self, call: CallFact) -> CallFact:
        if call.ref.symbol is None:
            return call
        symbol = self.model.canonical_symbol(call.ref.symbol)
        return (
            call
            if symbol == call.ref.symbol
            else replace(call, ref=replace(call.ref, symbol=symbol))
        )

    @cached_property
    def canonical_catalog(self) -> EffectCatalog:
        entries: dict[SymbolId, CatalogEntry] = {}
        for entry in self.catalog.entries.values():
            symbol = self.model.canonical_symbol(entry.symbol)
            canonical = CatalogEntry(symbol, entry.effects, entry.access_path)
            previous = entries.get(symbol)
            if previous is not None and previous != canonical:
                raise ValueError(f"conflicting effect catalog aliases for {symbol.value}")
            entries[symbol] = canonical
        return EffectCatalog(FrozenMap(entries))

    def symbol_in(self, symbol: SymbolId | None, candidates: frozenset[SymbolId]) -> bool:
        if symbol is None:
            return False
        canonical = self.model.canonical_symbol(symbol)
        return any(self.model.canonical_symbol(candidate) == canonical for candidate in candidates)

    def matching_symbol(
        self, symbol: SymbolId | None, candidates: tuple[SymbolId, ...] | frozenset[SymbolId]
    ) -> SymbolId | None:
        if symbol is None:
            return None
        canonical = self.model.canonical_symbol(symbol)
        return next(
            (
                candidate
                for candidate in candidates
                if (
                    canonical == self.model.canonical_symbol(candidate)
                    or canonical.value.startswith(
                        f"{self.model.canonical_symbol(candidate).value}."
                    )
                )
            ),
            None,
        )

    def approval_for(
        self,
        rule_id: RuleId,
        symbol: SymbolId,
        module_id: ModuleId,
        *,
        target: str | None = None,
        kind: str | None = None,
    ) -> PolicyApproval | None:
        zone = self.classification.get(module_id).zone
        canonical = self.model.canonical_symbol(symbol)
        return next(
            (
                approval
                for approval in self.policy.approvals
                if approval.rule_id == rule_id
                and self.model.canonical_symbol(approval.symbol) == canonical
                and zone in approval.zones
                and (kind is None or approval.kind == kind)
                and (approval.target is None or approval.target == target)
            ),
            None,
        )
