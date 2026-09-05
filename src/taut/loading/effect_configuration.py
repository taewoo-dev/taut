from __future__ import annotations

from taut.configuration.catalog import AccessPath, CatalogEntry, Effect, EffectCatalog
from taut.domain.frozen import FrozenMap
from taut.domain.ids import SymbolId
from taut.loading.builtin_catalog import builtin_catalog_entries
from taut.loading.config_values import reject_unknown as _reject_unknown
from taut.loading.config_values import string as _string
from taut.loading.config_values import strings as _strings
from taut.loading.config_values import table_list as _table_list
from taut.loading.errors import PolicyConfigError


def load_catalog(root: dict[str, object]) -> EffectCatalog:
    entries = {entry.symbol: entry for entry in builtin_catalog_entries()}
    for item in _table_list(root.get("effects", []), "effects"):
        _reject_unknown(item, frozenset({"symbol", "symbols", "effects", "access"}), "effects")
        if ("symbol" in item) == ("symbols" in item):
            raise PolicyConfigError("effects requires exactly one of symbol or symbols")
        symbols = (
            (_string(item["symbol"], "effects.symbol"),)
            if "symbol" in item
            else _strings(item["symbols"], "effects.symbols")
        )
        if not symbols:
            raise PolicyConfigError("effects.symbols must not be empty")
        try:
            effects = frozenset(
                Effect(value) for value in _strings(item.get("effects"), "effects.effects")
            )
            access_path = AccessPath(_string(item.get("access", "direct"), "effects.access"))
        except ValueError as error:
            raise PolicyConfigError(
                f"invalid effect catalog entry for {', '.join(symbols)}: {error}"
            ) from error
        for value in symbols:
            symbol = SymbolId(value)
            entry = CatalogEntry(symbol, effects, access_path)
            previous = entries.get(symbol)
            if previous is not None and previous != entry:
                raise PolicyConfigError(f"cannot override built-in effect: {symbol.value}")
            entries[symbol] = entry
    return EffectCatalog(FrozenMap(entries))
