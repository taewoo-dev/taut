from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from taut.analysis.semantic_model import SemanticModel
from taut.configuration.effective_policy import EffectivePolicy
from taut.configuration.manifest import ClassificationIndex
from taut.domain.facts import CallFact, ClassFact, FunctionFact, ResolutionState
from taut.domain.ids import SymbolId

_BASE_SETTINGS = frozenset(
    {
        SymbolId("pydantic_settings.BaseSettings"),
        SymbolId("pydantic_settings.main.BaseSettings"),
    }
)


def _canonical_set_cache() -> dict[frozenset[SymbolId], frozenset[SymbolId]]:
    return {}


def _matching_candidate_cache() -> dict[
    tuple[SymbolId, ...], tuple[tuple[SymbolId, SymbolId, str], ...]
]:
    return {}


@dataclass(frozen=True)
class PolicyIndexes:
    """Project-wide facts shared by rules during one policy run."""

    adapter_implementation_symbols: frozenset[SymbolId]
    settings_constructor_symbols: frozenset[SymbolId]
    functions_by_symbol: Mapping[SymbolId, FunctionFact]
    calls_by_symbol: Mapping[SymbolId, tuple[CallFact, ...]]
    classes_by_symbol: Mapping[SymbolId, ClassFact]
    class_bases: Mapping[SymbolId, frozenset[SymbolId]]
    class_ancestors: Mapping[SymbolId, frozenset[SymbolId]]
    logged_external_call_symbols: frozenset[SymbolId]
    logged_external_call_prefixes: tuple[str, ...]
    _canonical_sets: dict[frozenset[SymbolId], frozenset[SymbolId]] = field(
        default_factory=_canonical_set_cache, init=False, repr=False, compare=False
    )
    _matching_candidates: dict[tuple[SymbolId, ...], tuple[tuple[SymbolId, SymbolId, str], ...]] = (
        field(default_factory=_matching_candidate_cache, init=False, repr=False, compare=False)
    )

    def canonical_set(
        self, model: SemanticModel, candidates: frozenset[SymbolId]
    ) -> frozenset[SymbolId]:
        cached = self._canonical_sets.get(candidates)
        if cached is not None:
            return cached
        canonical = frozenset(model.canonical_symbol(item) for item in candidates)
        return self._canonical_sets.setdefault(candidates, canonical)

    def candidate_matchers(
        self,
        model: SemanticModel,
        candidates: tuple[SymbolId, ...] | frozenset[SymbolId],
    ) -> tuple[tuple[SymbolId, SymbolId, str], ...]:
        key = tuple(candidates)
        cached = self._matching_candidates.get(key)
        if cached is not None:
            return cached
        matchers = tuple(
            (candidate, canonical, f"{canonical.value}.")
            for candidate in key
            for canonical in (model.canonical_symbol(candidate),)
        )
        return self._matching_candidates.setdefault(key, matchers)

    def class_for(self, model: SemanticModel, symbol: SymbolId) -> ClassFact | None:
        return self.classes_by_symbol.get(model.canonical_symbol(symbol))

    def is_logged_external_call(self, call: CallFact) -> bool:
        symbol = call.ref.symbol
        if call.ref.state is not ResolutionState.RESOLVED or symbol is None:
            return False
        return symbol in self.logged_external_call_symbols or symbol.value.startswith(
            self.logged_external_call_prefixes
        )

    @classmethod
    def build(
        cls,
        model: SemanticModel,
        classification: ClassificationIndex,
        policy: EffectivePolicy,
    ) -> PolicyIndexes:
        adapter_symbols: set[SymbolId] = set()
        settings_symbols: set[SymbolId] = set(policy.boundaries.settings_constructors)
        functions_by_symbol: dict[SymbolId, FunctionFact] = {}
        calls_by_symbol: dict[SymbolId, list[CallFact]] = {}
        classes_by_symbol: dict[SymbolId, ClassFact] = {}
        class_bases: dict[SymbolId, frozenset[SymbolId]] = {}
        boundaries = policy.boundaries
        for module_id in model.modules():
            module = model.module(module_id)
            role = classification.get(module_id).role
            functions_by_symbol.update(
                (function.symbol_id, function) for function in module.functions
            )
            for call in module.calls:
                if call.ref.state is ResolutionState.RESOLVED and call.ref.symbol is not None:
                    calls_by_symbol.setdefault(call.ref.symbol, []).append(call)
            for class_fact in module.classes:
                canonical_class = model.canonical_symbol(class_fact.symbol_id)
                classes_by_symbol[canonical_class] = class_fact
                class_bases[canonical_class] = frozenset(
                    model.canonical_symbol(symbol)
                    for base in class_fact.bases
                    for symbol in base.symbols
                )
                if role in boundaries.adapter_roles and (
                    class_fact.symbol_id in boundaries.adapter_implementation_symbols
                    or class_fact.name.endswith(boundaries.adapter_implementation_suffixes)
                ):
                    adapter_symbols.add(class_fact.symbol_id)
                if any(
                    symbol in _BASE_SETTINGS for base in class_fact.bases for symbol in base.symbols
                ):
                    settings_symbols.add(class_fact.symbol_id)
        construction_targets = adapter_symbols.union(boundaries.external_client_constructors)
        construction_factories: set[SymbolId] = set()
        changed = True
        while changed:
            changed = False
            known_targets = construction_targets.union(construction_factories)
            for function in functions_by_symbol.values():
                canonical_returns = {
                    model.canonical_symbol(symbol) for symbol in function.returned_symbols
                }
                if (
                    function.symbol_id not in construction_factories
                    and canonical_returns.intersection(known_targets)
                ):
                    construction_factories.add(function.symbol_id)
                    changed = True
        adapter_symbols.update(construction_factories)
        class_ancestors: dict[SymbolId, frozenset[SymbolId]] = {}
        for symbol in classes_by_symbol:
            pending = list(class_bases.get(symbol, ()))
            ancestors: set[SymbolId] = set()
            while pending:
                parent = pending.pop()
                if parent in ancestors:
                    continue
                ancestors.add(parent)
                pending.extend(class_bases.get(parent, ()))
            class_ancestors[symbol] = frozenset(ancestors)
        return cls(
            adapter_implementation_symbols=frozenset(adapter_symbols),
            settings_constructor_symbols=frozenset(settings_symbols),
            functions_by_symbol=MappingProxyType(functions_by_symbol),
            calls_by_symbol=MappingProxyType(
                {symbol: tuple(calls) for symbol, calls in calls_by_symbol.items()}
            ),
            classes_by_symbol=MappingProxyType(classes_by_symbol),
            class_bases=MappingProxyType(class_bases),
            class_ancestors=MappingProxyType(class_ancestors),
            logged_external_call_symbols=frozenset(boundaries.logged_external_calls),
            logged_external_call_prefixes=tuple(
                f"{symbol.value}." for symbol in boundaries.logged_external_calls
            ),
        )
