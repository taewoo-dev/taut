"""Exact library value contracts; never use a callee's name as its return type."""

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
        "httpx.Response",
        "httpx.Cookies",
        "subprocess.Popen",
        "subprocess.CompletedProcess",
        "sqlalchemy.orm.Session",
        "sqlalchemy.ext.asyncio.AsyncSession",
        "fastapi.FastAPI",
        "fastapi.APIRouter",
        "starlette.applications.Starlette",
        "starlette.routing.Router",
        "pydantic.TypeAdapter",
        "builtins.dict",
        "builtins.list",
        "builtins.tuple",
        "builtins.str",
        "builtins.bytes",
    }
)


def constructed_type(symbol: SymbolId | None) -> SymbolId | None:
    return symbol if symbol is not None and symbol.value in _CONSTRUCTORS else None


_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "request", "send")
_RETURN_TYPES = {
    **{f"httpx.Client.{method}": "httpx.Response" for method in _HTTP_METHODS},
    **{f"requests.{method}": "requests.Response" for method in _HTTP_METHODS if method != "send"},
    **{f"requests.Session.{method}": "requests.Response" for method in _HTTP_METHODS},
    **{f"requests.sessions.Session.{method}": "requests.Response" for method in _HTTP_METHODS},
    "subprocess.run": "subprocess.CompletedProcess",
    "tortoise.connections.get": "tortoise.backends.base.client.BaseDBAsyncClient",
    "tortoise.Tortoise.get_connection": "tortoise.backends.base.client.BaseDBAsyncClient",
}
_AWAITED_RETURN_TYPES = {
    f"httpx.AsyncClient.{method}": "httpx.Response" for method in _HTTP_METHODS
}
_MEMBER_TYPES = {
    "httpx.Response.cookies": "httpx.Cookies",
    "requests.Response.cookies": "requests.cookies.RequestsCookieJar",
    "subprocess.Popen.stdin": "io.IOBase",
    "subprocess.Popen.stdout": "io.IOBase",
    "subprocess.Popen.stderr": "io.IOBase",
}
_SELF_CONTEXT_MANAGERS = frozenset(
    {
        "httpx.Client",
        "httpx.AsyncClient",
        "requests.Session",
        "requests.sessions.Session",
        "subprocess.Popen",
    }
)


def returned_type(symbol: SymbolId, *, awaited: bool = False) -> SymbolId | None:
    if not awaited and (constructor := constructed_type(symbol)) is not None:
        return constructor
    values = _AWAITED_RETURN_TYPES if awaited else _RETURN_TYPES
    value = values.get(symbol.value)
    return SymbolId(value) if value is not None else None


def member_type(owner: SymbolId, name: str) -> SymbolId | None:
    value = _MEMBER_TYPES.get(f"{owner.value}.{name}")
    return SymbolId(value) if value is not None else None


def context_item_type(symbol: SymbolId) -> SymbolId | None:
    return symbol if symbol.value in _SELF_CONTEXT_MANAGERS else None
