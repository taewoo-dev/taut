from __future__ import annotations

from taut.configuration.catalog import AccessPath, CatalogEntry, Effect
from taut.domain.ids import SymbolId


def _direct(symbol: str, *effects: Effect) -> CatalogEntry:
    return CatalogEntry(SymbolId(symbol), frozenset(effects), AccessPath.DIRECT)


def builtin_catalog_entries() -> tuple[CatalogEntry, ...]:
    entries = [
        _direct("datetime.datetime.now", Effect.TIME_NOW),
        _direct("datetime.datetime.utcnow", Effect.TIME_NOW),
        _direct("datetime.datetime.today", Effect.TIME_NOW),
        _direct("datetime.date.today", Effect.TIME_NOW),
        _direct("sqlalchemy.ext.asyncio.AsyncSession.commit", Effect.TX_COMMIT),
        _direct("sqlalchemy.ext.asyncio.AsyncSession.rollback", Effect.TX_ROLLBACK),
        _direct(
            "tortoise.backends.base.client.TransactionalDBClient.commit",
            Effect.TX_COMMIT,
        ),
        _direct(
            "tortoise.backends.base.client.TransactionalDBClient.rollback",
            Effect.TX_ROLLBACK,
        ),
        _direct("time.sleep", Effect.IO_BLOCKING),
        _direct("builtins.open", Effect.IO_BLOCKING),
        _direct("os.getenv", Effect.SECURITY_ENVIRONMENT),
        _direct("os.environ.get", Effect.SECURITY_ENVIRONMENT),
        _direct("jwt.encode", Effect.SECURITY_TOKEN),
        _direct("jwt.decode", Effect.SECURITY_TOKEN),
        _direct("jose.jwt.encode", Effect.SECURITY_TOKEN),
        _direct("jose.jwt.decode", Effect.SECURITY_TOKEN),
    ]
    for name in ("run", "call", "check_call", "check_output"):
        entries.append(_direct(f"subprocess.{name}", Effect.IO_BLOCKING))
    for owner in ("pathlib.Path", "pathlib.PosixPath", "pathlib.WindowsPath"):
        for method in ("read_text", "read_bytes", "write_text", "write_bytes", "open", "stat"):
            entries.append(_direct(f"{owner}.{method}", Effect.IO_BLOCKING))
    for owner in ("requests.Session", "requests.sessions.Session"):
        for method in (
            "get",
            "post",
            "put",
            "delete",
            "patch",
            "head",
            "options",
            "request",
            "send",
        ):
            entries.append(_direct(f"{owner}.{method}", Effect.IO_BLOCKING, Effect.EXTERNAL_CALL))
    for name in ("Popen", "Popen.communicate", "Popen.wait"):
        entries.append(_direct(f"subprocess.{name}", Effect.IO_BLOCKING))
    for name in ("get", "post", "put", "delete", "patch", "head", "options", "request"):
        entries.append(
            _direct(
                f"requests.{name}",
                Effect.IO_BLOCKING,
                Effect.EXTERNAL_CALL,
            )
        )
    http_methods = ("get", "post", "put", "delete", "patch", "head", "options", "request", "send")
    for name in http_methods:
        entries.append(
            _direct(
                f"httpx.Client.{name}",
                Effect.IO_BLOCKING,
                Effect.EXTERNAL_CALL,
            )
        )
        entries.append(_direct(f"httpx.AsyncClient.{name}", Effect.EXTERNAL_CALL))
        entries.append(_direct(f"aiohttp.ClientSession.{name}", Effect.EXTERNAL_CALL))
    return tuple(sorted(entries, key=lambda entry: entry.symbol))
