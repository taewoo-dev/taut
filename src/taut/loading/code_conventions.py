from __future__ import annotations

from collections.abc import Iterable
from typing import cast

from taut.configuration.effective_policy import CodeConventionPolicy
from taut.configuration.manifest import Role
from taut.domain.ids import ModuleId, SymbolId
from taut.domain.location import ProjectPath
from taut.loading.errors import PolicyConfigError

_KEYS = frozenset(
    {
        "dto_roles",
        "schema_roles",
        "router_roles",
        "service_roles",
        "model_roles",
        "snapshot_roles",
        "request_config_symbols",
        "response_config_symbols",
        "shared_enum_modules",
        "uppercase_enum_exceptions",
        "non_str_enum_exceptions",
        "native_enum_false_exceptions",
        "native_enum_no_constraint_exceptions",
        "generic_schema_bases",
        "forbidden_runtime_calls",
        "exception_base_symbols",
        "abstract_exception_symbols",
        "error_code_enum_symbols",
        "reserved_error_code_symbols",
        "dto_name_suffixes",
        "test_root_paths",
        "raw_test_http_calls",
        "raw_test_http_client_constructors",
        "test_http_fixture_roles",
    }
)


def _table(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise PolicyConfigError("code_conventions must be a table")
    unknown = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in unknown):
        raise PolicyConfigError("code_conventions must be a table")
    return cast(dict[str, object], value)


def _strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise PolicyConfigError(f"{label} must be an array of non-empty strings")
    items = cast(list[object], value)
    if not all(isinstance(item, str) and item.strip() for item in items):
        raise PolicyConfigError(f"{label} must be an array of non-empty strings")
    return tuple(cast(list[str], items))


def _unique(values: Iterable[str], label: str) -> None:
    sequence = tuple(values)
    if len(sequence) != len(set(sequence)):
        raise PolicyConfigError(f"duplicate {label} name")


def load_code_conventions(value: object) -> CodeConventionPolicy:
    table = _table(value)
    unknown = set(table).difference(_KEYS)
    if unknown:
        raise PolicyConfigError(f"unknown code_conventions keys: {', '.join(sorted(unknown))}")

    def values(name: str, default: list[str] | None = None) -> tuple[str, ...]:
        result = _strings(table.get(name, default or []), f"code_conventions.{name}")
        _unique(result, f"code_conventions.{name}")
        return result

    def roles(name: str, default: list[str]) -> frozenset[Role]:
        return frozenset(Role(item) for item in set(default).union(values(name)))

    def symbols(name: str) -> frozenset[SymbolId]:
        return frozenset(SymbolId(item) for item in values(name))

    def locked_values(name: str, defaults: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(defaults).union(values(name))))

    return CodeConventionPolicy(
        dto_roles=roles("dto_roles", ["dto"]),
        schema_roles=roles("schema_roles", ["schema"]),
        router_roles=roles("router_roles", ["router"]),
        service_roles=roles("service_roles", ["service"]),
        model_roles=roles("model_roles", ["model"]),
        snapshot_roles=roles("snapshot_roles", ["snapshot"]),
        request_config_symbols=symbols("request_config_symbols"),
        response_config_symbols=symbols("response_config_symbols"),
        shared_enum_modules=tuple(sorted(ModuleId(item) for item in values("shared_enum_modules"))),
        uppercase_enum_exceptions=symbols("uppercase_enum_exceptions"),
        non_str_enum_exceptions=symbols("non_str_enum_exceptions"),
        native_enum_false_exceptions=symbols("native_enum_false_exceptions"),
        native_enum_no_constraint_exceptions=symbols("native_enum_no_constraint_exceptions"),
        generic_schema_bases=symbols("generic_schema_bases"),
        forbidden_runtime_calls=tuple(sorted(values("forbidden_runtime_calls"))),
        exception_base_symbols=symbols("exception_base_symbols"),
        abstract_exception_symbols=symbols("abstract_exception_symbols"),
        error_code_enum_symbols=symbols("error_code_enum_symbols"),
        reserved_error_code_symbols=symbols("reserved_error_code_symbols"),
        dto_name_suffixes=locked_values("dto_name_suffixes", ("Data", "Result", "Row")),
        test_root_paths=tuple(
            ProjectPath(item) for item in locked_values("test_root_paths", ("tests",))
        ),
        raw_test_http_calls=tuple(
            SymbolId(item)
            for item in locked_values(
                "raw_test_http_calls",
                tuple(
                    f"httpx.AsyncClient.{method}"
                    for method in (
                        "delete",
                        "get",
                        "head",
                        "options",
                        "patch",
                        "post",
                        "put",
                        "request",
                        "send",
                    )
                ),
            )
        ),
        raw_test_http_client_constructors=tuple(
            SymbolId(item)
            for item in locked_values(
                "raw_test_http_client_constructors",
                ("httpx.AsyncClient", "httpx.Client"),
            )
        ),
        test_http_fixture_roles=roles("test_http_fixture_roles", []),
    )
