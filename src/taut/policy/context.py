from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
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
from taut.policy.atomicity_summaries import (
    AtomicitySummaryState,
    build_atomicity_summary_state,
)
from taut.policy.function_summaries import (
    FunctionSemanticSummary,
    FunctionSummaryState,
    build_function_summary_state,
)
from taut.policy.indexes import PolicyIndexes
from taut.policy.symbol_contracts import SymbolContractIndex


def _effect_resolution_cache() -> dict[FactId, EffectResolution]:
    return {}


@dataclass(frozen=True)
class PolicyContext:
    model: SemanticModel
    classification: ClassificationIndex
    effects: EffectResolver
    catalog: EffectCatalog
    policy: EffectivePolicy
    prior_function_summary_state: FunctionSummaryState | None = field(
        default=None, repr=False, compare=False
    )
    function_summary_invalidated_modules: frozenset[ModuleId] | None = field(
        default=None, repr=False, compare=False
    )
    prior_atomicity_summary_state: AtomicitySummaryState | None = field(
        default=None, repr=False, compare=False
    )
    atomicity_summary_invalidated_modules: frozenset[ModuleId] | None = field(
        default=None, repr=False, compare=False
    )
    _effect_resolution_cache: dict[FactId, EffectResolution] = field(
        default_factory=_effect_resolution_cache, init=False, repr=False, compare=False
    )

    @cached_property
    def indexes(self) -> PolicyIndexes:
        return PolicyIndexes.build(self.model, self.classification, self.policy)

    @cached_property
    def symbol_contracts(self) -> SymbolContractIndex:
        return SymbolContractIndex.build(self.model, self.classification, self.policy, self.indexes)

    @cached_property
    def effect_resolutions(self) -> Mapping[FactId, EffectResolution]:
        """Resolve all calls while retaining the lazy per-revision cache."""
        for module_id in self.model.modules():
            for call in self.model.module(module_id).calls:
                self.effect_of(call)
        return MappingProxyType(self._effect_resolution_cache)

    def effect_of(self, call: CallFact) -> EffectResolution:
        resolution = self._effect_resolution_cache.get(call.id)
        if resolution is None:
            resolution = self.effects.resolve(self._canonical_call(call), self.canonical_catalog)
            self._effect_resolution_cache[call.id] = resolution
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
    def function_summary_state(self) -> FunctionSummaryState:
        return build_function_summary_state(
            self,
            self.prior_function_summary_state,
            self.function_summary_invalidated_modules,
        )

    @property
    def function_summaries(self) -> Mapping[SymbolId, FunctionSemanticSummary]:
        return self.function_summary_state.summaries

    @cached_property
    def atomicity_summary_state(self) -> AtomicitySummaryState:
        return build_atomicity_summary_state(
            self,
            self.prior_atomicity_summary_state,
            self.atomicity_summary_invalidated_modules,
        )

    def cached_atomicity_summary_state(self) -> AtomicitySummaryState | None:
        value = self.__dict__.get("atomicity_summary_state")
        return value if isinstance(value, AtomicitySummaryState) else None

    def transitive_effect_of(self, call: CallFact) -> EffectResolution:
        """Resolve configured effects or effects derived from project-owned callees."""
        direct = self.effect_of(call)
        if direct.state is not EffectResolutionState.NO_MATCH or call.ref.symbol is None:
            return direct
        summary = self.function_summaries.get(self.model.canonical_symbol(call.ref.symbol))
        if summary is None or not summary.effects:
            return direct
        accesses = frozenset(summary.effect_access.values())
        access = (
            AccessPath.APPROVED_WRAPPER
            if accesses == frozenset({AccessPath.APPROVED_WRAPPER})
            else AccessPath.DIRECT
        )
        return EffectResolution(
            EffectResolutionState.MATCHED,
            summary.effects,
            access,
            self.model.canonical_symbol(call.ref.symbol)
            if access is AccessPath.APPROVED_WRAPPER
            else None,
        )

    def function_summary(self, symbol: SymbolId | None) -> FunctionSemanticSummary | None:
        if symbol is None:
            return None
        return self.function_summaries.get(self.model.canonical_symbol(symbol))

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

    def tortoise_query(self, fact_id: FactId) -> TortoiseQueryFact | None:
        return self.tortoise_queries.get(fact_id)

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
        return canonical in self.indexes.canonical_set(self.model, candidates)

    def symbol_in_or_inherits(
        self, symbol: SymbolId | None, candidates: frozenset[SymbolId]
    ) -> bool:
        if symbol is None:
            return False
        wanted = self.indexes.canonical_set(self.model, candidates)
        current = self.model.canonical_symbol(symbol)
        return current in wanted or not self.indexes.class_ancestors.get(
            current, frozenset()
        ).isdisjoint(wanted)

    def matching_symbol(
        self, symbol: SymbolId | None, candidates: tuple[SymbolId, ...] | frozenset[SymbolId]
    ) -> SymbolId | None:
        if symbol is None:
            return None
        canonical = self.model.canonical_symbol(symbol)
        return next(
            (
                candidate
                for candidate, expected, prefix in self.indexes.candidate_matchers(
                    self.model, candidates
                )
                if canonical == expected or canonical.value.startswith(prefix)
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
