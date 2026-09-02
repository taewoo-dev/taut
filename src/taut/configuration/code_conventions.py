from __future__ import annotations

from dataclasses import dataclass

from taut.configuration.manifest import Role
from taut.domain.ids import ModuleId, SymbolId
from taut.domain.location import ProjectPath


@dataclass(frozen=True)
class CodeConventionPolicy:
    dto_roles: frozenset[Role] = frozenset()
    schema_roles: frozenset[Role] = frozenset()
    router_roles: frozenset[Role] = frozenset()
    service_roles: frozenset[Role] = frozenset()
    model_roles: frozenset[Role] = frozenset()
    snapshot_roles: frozenset[Role] = frozenset()
    request_config_symbols: frozenset[SymbolId] = frozenset()
    response_config_symbols: frozenset[SymbolId] = frozenset()
    shared_enum_modules: tuple[ModuleId, ...] = ()
    uppercase_enum_exceptions: frozenset[SymbolId] = frozenset()
    non_str_enum_exceptions: frozenset[SymbolId] = frozenset()
    native_enum_false_exceptions: frozenset[SymbolId] = frozenset()
    native_enum_no_constraint_exceptions: frozenset[SymbolId] = frozenset()
    generic_schema_bases: frozenset[SymbolId] = frozenset()
    forbidden_runtime_calls: tuple[str, ...] = ()
    exception_base_symbols: frozenset[SymbolId] = frozenset()
    abstract_exception_symbols: frozenset[SymbolId] = frozenset()
    error_code_enum_symbols: frozenset[SymbolId] = frozenset()
    reserved_error_code_symbols: frozenset[SymbolId] = frozenset()
    dto_base_symbols: frozenset[SymbolId] = frozenset()
    response_mapper_name: str = "from_internal"
    exception_code_argument_names: tuple[str, ...] = ("error_code",)
    exception_code_field_names: tuple[str, ...] = ("code",)
    dto_name_suffixes: tuple[str, ...] = ("Data", "Result", "Row")
    test_root_paths: tuple[ProjectPath, ...] = (ProjectPath("tests"),)
    raw_test_http_calls: tuple[SymbolId, ...] = ()
    raw_test_http_client_constructors: tuple[SymbolId, ...] = ()
    test_http_fixture_roles: frozenset[Role] = frozenset()
    test_http_fixture_symbols: frozenset[SymbolId] = frozenset()

    def __post_init__(self) -> None:
        if self.shared_enum_modules != tuple(sorted(set(self.shared_enum_modules))):
            raise ValueError("shared enum modules must be unique and sorted")
        if self.dto_name_suffixes != tuple(sorted(set(self.dto_name_suffixes))):
            raise ValueError("DTO name suffixes must be unique and sorted")
        if any(not suffix.strip() for suffix in self.dto_name_suffixes):
            raise ValueError("DTO name suffix cannot be empty")
        if not self.response_mapper_name.isidentifier():
            raise ValueError("response mapper name must be a Python identifier")
        for label, values in (
            ("exception code argument", self.exception_code_argument_names),
            ("exception code field", self.exception_code_field_names),
        ):
            if values != tuple(sorted(set(values))) or any(
                not value.isidentifier() for value in values
            ):
                raise ValueError(f"{label} names must be unique sorted Python identifiers")
        if self.forbidden_runtime_calls != tuple(sorted(set(self.forbidden_runtime_calls))):
            raise ValueError("forbidden runtime calls must be unique and sorted")
        if self.test_root_paths != tuple(sorted(set(self.test_root_paths))):
            raise ValueError("test root paths must be unique and sorted")
        if self.raw_test_http_calls != tuple(sorted(set(self.raw_test_http_calls))):
            raise ValueError("raw test HTTP calls must be unique and sorted")
        if self.raw_test_http_client_constructors != tuple(
            sorted(set(self.raw_test_http_client_constructors))
        ):
            raise ValueError("raw test HTTP client constructors must be unique and sorted")
