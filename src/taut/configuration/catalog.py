from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from taut.domain.facts import CallFact, ResolutionState
from taut.domain.frozen import FrozenMap
from taut.domain.ids import SymbolId


class Effect(StrEnum):
    """Closed operation vocabulary understood by built-in policy rules."""

    TIME_NOW = "time.now"
    TX_COMMIT = "tx.commit"
    TX_ROLLBACK = "tx.rollback"
    IO_BLOCKING = "io.blocking"
    EXTERNAL_CALL = "external.call"
    SECURITY_ENVIRONMENT = "security.environment"
    SECURITY_SECRET = "security.secret"
    SECURITY_TOKEN = "security.token"


class AccessPath(StrEnum):
    DIRECT = "direct"
    APPROVED_WRAPPER = "approved_wrapper"


@dataclass(frozen=True, order=True)
class CatalogEntry:
    symbol: SymbolId
    effects: frozenset[Effect]
    access_path: AccessPath

    def __post_init__(self) -> None:
        if not self.effects:
            raise ValueError("catalog entry requires at least one effect")


@dataclass(frozen=True)
class EffectCatalog:
    entries: FrozenMap[SymbolId, CatalogEntry]

    def __post_init__(self) -> None:
        if any(symbol != entry.symbol for symbol, entry in self.entries.items()):
            raise ValueError("effect catalog key must match entry symbol")


class EffectResolutionState(StrEnum):
    MATCHED = "matched"
    NO_MATCH = "no_match"
    AMBIGUOUS = "ambiguous"
    SYMBOL_UNRESOLVED = "symbol_unresolved"


@dataclass(frozen=True)
class EffectResolution:
    state: EffectResolutionState
    effects: frozenset[Effect]
    access_path: AccessPath | None
    wrapper: SymbolId | None

    def __post_init__(self) -> None:
        if self.state is EffectResolutionState.MATCHED:
            if not self.effects or self.access_path is None:
                raise ValueError("matched effect resolution requires effects and access path")
        elif self.effects or self.access_path is not None or self.wrapper is not None:
            raise ValueError("unmatched effect resolution cannot contain operation values")


@dataclass(frozen=True)
class OperationView:
    call: CallFact
    effects: frozenset[Effect]
    access_path: AccessPath
    wrapper: SymbolId | None


class EffectResolver:
    def resolve(self, call: CallFact, catalog: EffectCatalog) -> EffectResolution:
        if call.ref.state is not ResolutionState.RESOLVED or call.ref.symbol is None:
            return EffectResolution(
                EffectResolutionState.SYMBOL_UNRESOLVED,
                frozenset(),
                None,
                None,
            )
        entry = catalog.entries.get(call.ref.symbol)
        if entry is None:
            return EffectResolution(
                EffectResolutionState.NO_MATCH,
                frozenset(),
                None,
                None,
            )
        wrapper = entry.symbol if entry.access_path is AccessPath.APPROVED_WRAPPER else None
        return EffectResolution(
            EffectResolutionState.MATCHED,
            entry.effects,
            entry.access_path,
            wrapper,
        )
