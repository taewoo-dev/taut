from __future__ import annotations

from dataclasses import dataclass, field
from typing import cast

from taut.analysis.framework.fastapi import FASTAPI_ROUTERS, FastAPIProvider, FastAPIRouterFact
from taut.analysis.framework.sqlalchemy import SQLALCHEMY_MODELS, SQLAlchemyProvider
from taut.analysis.framework.sqlalchemy_facts import MODEL_BASES, SQLAlchemyModelFact
from taut.analysis.providers import CapabilityValues, IncrementalFactProviderV1
from taut.domain.ids import ModuleId
from taut.domain.snapshot import AnalysisSnapshot


@dataclass
class ProviderReuseCounters:
    recomputed_modules: dict[str, int] = field(default_factory=lambda: dict[str, int]())
    reused_exports: set[str] = field(default_factory=lambda: set[str]())


def local_provider_result(
    provider: IncrementalFactProviderV1,
    snapshot: AnalysisSnapshot,
    prior: AnalysisSnapshot,
    previous: CapabilityValues,
    impacted: frozenset[ModuleId],
    *,
    counters: ProviderReuseCounters | None = None,
) -> CapabilityValues | None:
    """Stop propagation only when the built-in provider's exported input is equal.

    Never selected by provider ID: third-party implementations retain their contract.
    The changed modules always get fresh facts, locations and source provenance.
    """
    if counters is not None:
        counters.recomputed_modules[provider.id] = len(impacted)
    if type(provider) not in (FastAPIProvider, SQLAlchemyProvider):
        return None
    if snapshot.modules.keys() != prior.modules.keys():
        return None
    changed = frozenset(
        module
        for module in snapshot.modules
        if snapshot.modules[module] is not prior.modules[module]
    )
    if not changed < impacted:
        return None
    if type(provider) is SQLAlchemyProvider and any(
        call.ref.symbol is not None and call.ref.symbol.value in MODEL_BASES
        for module in changed
        for facts in (snapshot.modules[module], prior.modules[module])
        for call in facts.calls
    ):
        # Declarative-base factories export a symbol even without a model fact.
        return None
    candidate = provider.analyze_incremental(snapshot, previous, changed)
    if type(provider) is FastAPIProvider:
        old = frozenset(
            item.symbol for item in cast(tuple[FastAPIRouterFact, ...], previous[FASTAPI_ROUTERS])
        )
        new = frozenset(
            item.symbol for item in cast(tuple[FastAPIRouterFact, ...], candidate[FASTAPI_ROUTERS])
        )
    else:
        old = frozenset(
            item.symbol
            for item in cast(tuple[SQLAlchemyModelFact, ...], previous[SQLALCHEMY_MODELS])
        )
        new = frozenset(
            item.symbol
            for item in cast(tuple[SQLAlchemyModelFact, ...], candidate[SQLALCHEMY_MODELS])
        )
    if old != new:
        return None
    if counters is not None:
        counters.recomputed_modules[provider.id] = len(changed)
        counters.reused_exports.add(provider.id)
    return candidate
