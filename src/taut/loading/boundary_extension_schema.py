from __future__ import annotations

BOUNDARY_EXTENSION_KEYS = frozenset(
    {
        "entry_roles",
        "service_roles",
        "contract_roles",
        "adapter_roles",
        "query_roles",
        "model_roles",
        "bootstrap_roles",
        "implementation_construction_roles",
        "configuration_roles",
        "raw_query_roles",
        "external_modules",
        "database_modules",
        "transport_modules",
        "contract_forbidden_modules",
        "adapter_forbidden_modules",
        "adapter_forbidden_calls",
        "database_statement_calls",
        "transport_exception_calls",
        "dependency_injection_calls",
        "external_client_constructors",
        "adapter_implementation_symbols",
        "adapter_implementation_suffixes",
        "settings_constructors",
        "session_type_symbols",
        "raw_sql_calls",
        "raw_query_wrappers",
        "schema_sql_roles",
        "schema_sql_argument_names",
        "raw_sql_execution_methods",
        "database_owner_names",
        "database_primitive_methods",
        "query_write_method_prefixes",
        "http_timeout_calls",
        "logged_external_calls",
        "external_call_wrappers",
    }
)

__all__ = ["BOUNDARY_EXTENSION_KEYS"]
