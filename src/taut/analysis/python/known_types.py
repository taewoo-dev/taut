"""Exact library constructor identities; never infer types from capitalization."""

from taut.domain.ids import SymbolId

_CONSTRUCTORS = frozenset(
    {
        "pathlib.Path",
        "pathlib.PosixPath",
        "pathlib.WindowsPath",
        "requests.Session",
        "requests.sessions.Session",
        "httpx.Client",
        "httpx.AsyncClient",
    }
)


def constructed_type(symbol: SymbolId | None) -> SymbolId | None:
    return symbol if symbol is not None and symbol.value in _CONSTRUCTORS else None
