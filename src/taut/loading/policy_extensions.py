from __future__ import annotations

from taut.configuration.catalog import Effect
from taut.configuration.effective_policy import BoundaryPolicy, PolicyApproval, SecurityPolicy
from taut.configuration.manifest import Role, Zone
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, RuleId, SymbolId
from taut.loading.boundary_extension_schema import BOUNDARY_EXTENSION_KEYS
from taut.loading.config_values import (
    ensure_unique,
    reject_unknown,
    string,
    strings,
    table,
    table_list,
)
from taut.loading.errors import PolicyConfigError

KNOWN_ZONES = frozenset({"prod", "test", "migration", "script"})
_RISKY_PREFIXES = (
    "httpx.AsyncClient.",
    "httpx.Client.",
    "requests.",
    "subprocess.",
)


def load_rule_zones(
    root: dict[str, object], known_rules: set[str]
) -> FrozenMap[RuleId, frozenset[Zone]]:
    values = table(root.get("rule_zones", {}), "rule_zones")
    unknown = set(values).difference(known_rules)
    if unknown:
        raise PolicyConfigError(f"unknown rule_zones rules: {', '.join(sorted(unknown))}")
    configured_zones: list[tuple[RuleId, frozenset[Zone]]] = []
    for rule, raw_zones in values.items():
        configured = strings(raw_zones, f"rule_zones.{rule}")
        if not configured:
            raise PolicyConfigError(f"rule_zones.{rule} requires at least one zone")
        zones = frozenset(Zone(value) for value in configured)
        unknown_zones = {zone.value for zone in zones}.difference(KNOWN_ZONES)
        if unknown_zones:
            raise PolicyConfigError(
                f"unknown rule_zones.{rule} zones: {', '.join(sorted(unknown_zones))}"
            )
        configured_zones.append((RuleId(rule), zones))
    return FrozenMap(configured_zones)


def load_approvals(root: dict[str, object], known_rules: set[str]) -> tuple[PolicyApproval, ...]:
    approvals: list[PolicyApproval] = []
    for item in table_list(root.get("approvals", []), "approvals"):
        reject_unknown(
            item,
            frozenset({"rule", "symbol", "target", "kind", "zones", "reason"}),
            "approvals",
        )
        rule = string(item.get("rule"), "approvals.rule")
        if rule not in known_rules or rule == "IGNORE001":
            raise PolicyConfigError(f"unknown approval rule: {rule}")
        raw_zones = strings(
            item.get("zones", ["prod", "test", "migration", "script"]),
            "approvals.zones",
        )
        zones = frozenset(Zone(value) for value in raw_zones)
        unknown_zones = {zone.value for zone in zones}.difference(KNOWN_ZONES)
        if unknown_zones:
            raise PolicyConfigError(f"unknown approval zones: {', '.join(sorted(unknown_zones))}")
        target_value = item.get("target")
        target = string(target_value, "approvals.target") if target_value is not None else None
        approvals.append(
            PolicyApproval(
                rule_id=RuleId(rule),
                symbol=SymbolId(string(item.get("symbol"), "approvals.symbol")),
                target=target,
                kind=string(item.get("kind", "allow"), "approvals.kind"),
                zones=zones,
                reason=string(item.get("reason"), "approvals.reason"),
            )
        )
    ordered = tuple(sorted(approvals, key=lambda approval: approval.key))
    ensure_unique((approval.key for approval in ordered), "approval")
    return ordered


def load_boundary_extensions(root: dict[str, object]) -> BoundaryPolicy:
    values = table(root.get("boundary_extensions", {}), "boundary_extensions")
    reject_unknown(values, BOUNDARY_EXTENSION_KEYS, "boundary_extensions")

    def roles(name: str, defaults: tuple[str, ...] = ()) -> frozenset[Role]:
        additions = strings(values.get(name, []), f"boundary_extensions.{name}")
        return frozenset(Role(value) for value in set(defaults).union(additions))

    def modules(name: str, defaults: tuple[str, ...] = ()) -> tuple[ModuleId, ...]:
        additions = strings(values.get(name, []), f"boundary_extensions.{name}")
        return tuple(sorted(ModuleId(value) for value in set(defaults).union(additions)))

    def symbols(name: str, defaults: tuple[str, ...] = ()) -> tuple[SymbolId, ...]:
        additions = strings(values.get(name, []), f"boundary_extensions.{name}")
        return tuple(sorted(SymbolId(value) for value in set(defaults).union(additions)))

    def names(name: str, defaults: tuple[str, ...] = ()) -> tuple[str, ...]:
        additions = strings(values.get(name, []), f"boundary_extensions.{name}")
        return tuple(sorted(set(defaults).union(additions)))

    return BoundaryPolicy(
        entry_roles=roles("entry_roles", ("consumer", "router", "task")),
        service_roles=roles("service_roles", ("service",)),
        contract_roles=roles("contract_roles", ("contract",)),
        adapter_roles=roles("adapter_roles", ("adapter",)),
        query_roles=roles("query_roles", ("queries", "query")),
        model_roles=roles("model_roles", ("model",)),
        bootstrap_roles=roles("bootstrap_roles", ("bootstrap", "composition")),
        implementation_construction_roles=roles("implementation_construction_roles"),
        scoped_construction_roles=roles("scoped_construction_roles", ("adapter",)),
        configuration_roles=roles("configuration_roles", ("configuration",)),
        dependency_registration_roles=roles(
            "dependency_registration_roles", ("bootstrap", "composition")
        ),
        raw_query_roles=roles("raw_query_roles", ("raw_query",)),
        external_modules=modules(
            "external_modules",
            ("aiohttp", "anthropic", "boto3", "httpx", "openai", "requests"),
        ),
        database_modules=modules("database_modules", ("sqlalchemy", "tortoise")),
        transport_modules=modules("transport_modules", ("fastapi", "starlette")),
        contract_forbidden_modules=modules(
            "contract_forbidden_modules",
            ("anthropic", "fastapi", "httpx", "openai", "sqlalchemy", "tortoise"),
        ),
        adapter_forbidden_modules=modules("adapter_forbidden_modules", ("sqlalchemy", "tortoise")),
        adapter_forbidden_calls=symbols(
            "adapter_forbidden_calls",
            (
                "sqlalchemy.ext.asyncio.AsyncSession.add",
                "sqlalchemy.ext.asyncio.AsyncSession.commit",
                "sqlalchemy.ext.asyncio.AsyncSession.execute",
                "sqlalchemy.ext.asyncio.AsyncSession.flush",
                "sqlalchemy.ext.asyncio.AsyncSession.rollback",
                "tortoise.backends.base.client.BaseDBAsyncClient.execute_insert",
                "tortoise.backends.base.client.BaseDBAsyncClient.execute_many",
                "tortoise.backends.base.client.BaseDBAsyncClient.execute_query",
                "tortoise.backends.base.client.BaseDBAsyncClient.execute_script",
                "tortoise.backends.base.client.TransactionalDBClient.commit",
                "tortoise.backends.base.client.TransactionalDBClient.execute_insert",
                "tortoise.backends.base.client.TransactionalDBClient.execute_many",
                "tortoise.backends.base.client.TransactionalDBClient.execute_query",
                "tortoise.backends.base.client.TransactionalDBClient.execute_script",
                "tortoise.backends.base.client.TransactionalDBClient.rollback",
            ),
        ),
        database_statement_calls=symbols(
            "database_statement_calls",
            (
                "sqlalchemy.delete",
                "sqlalchemy.insert",
                "sqlalchemy.scoped_query",
                "sqlalchemy.select",
                "sqlalchemy.update",
                "tortoise.models.Model.bulk_create",
                "tortoise.models.Model.bulk_update",
                "tortoise.models.Model.create",
                "tortoise.models.Model.delete",
                "tortoise.models.Model.filter",
                "tortoise.models.Model.get",
                "tortoise.models.Model.get_or_create",
                "tortoise.models.Model.update_or_create",
                "tortoise.queryset.QuerySet.delete",
                "tortoise.queryset.QuerySet.filter",
                "tortoise.queryset.QuerySet.update",
            ),
        ),
        transport_exception_calls=symbols(
            "transport_exception_calls",
            ("fastapi.HTTPException", "starlette.exceptions.HTTPException"),
        ),
        dependency_injection_calls=symbols(
            "dependency_injection_calls", ("fastapi.Depends", "fastapi.params.Depends")
        ),
        external_client_constructors=symbols(
            "external_client_constructors",
            (
                "aiohttp.ClientSession",
                "httpx.AsyncClient",
                "httpx.Client",
                "openai.AsyncOpenAI",
                "openai.OpenAI",
            ),
        ),
        adapter_implementation_symbols=frozenset(symbols("adapter_implementation_symbols")),
        adapter_implementation_suffixes=names(
            "adapter_implementation_suffixes", ("Adapter", "Client", "Gateway", "Harness")
        ),
        settings_constructors=symbols("settings_constructors"),
        session_type_symbols=symbols(
            "session_type_symbols",
            (
                "sqlalchemy.ext.asyncio.AsyncSession",
                "sqlalchemy.orm.Session",
                "tortoise.backends.base.client.TransactionalDBClient",
            ),
        ),
        raw_sql_calls=symbols(
            "raw_sql_calls",
            (
                "sqlalchemy.sql.expression.text",
                "sqlalchemy.text",
                "tortoise.expressions.RawSQL",
                "tortoise.models.Model.raw",
            ),
        ),
        raw_query_wrappers=frozenset(symbols("raw_query_wrappers")),
        schema_sql_roles=roles("schema_sql_roles", ("model",)),
        schema_sql_argument_names=names(
            "schema_sql_argument_names", ("postgresql_where", "server_default", "sqlite_where")
        ),
        schema_sql_parent_calls=symbols(
            "schema_sql_parent_calls", ("sqlalchemy.Index", "sqlalchemy.sql.schema.Index")
        ),
        raw_sql_execution_methods=names(
            "raw_sql_execution_methods",
            (
                "exec_driver_sql",
                "execute",
                "execute_insert",
                "execute_many",
                "execute_query",
                "execute_query_dict",
                "execute_script",
                "raw",
            ),
        ),
        database_owner_names=names("database_owner_names", ("conn", "connection", "db", "session")),
        database_primitive_methods=names(
            "database_primitive_methods",
            (
                "add",
                "add_all",
                "bulk_create",
                "bulk_update",
                "create",
                "delete",
                "execute",
                "filter",
                "flush",
                "get",
                "get_or_create",
                "merge",
                "save",
                "update",
                "update_or_create",
            ),
        ),
        query_write_method_prefixes=names(
            "query_write_method_prefixes",
            (
                "add_",
                "create_",
                "delete_",
                "insert_",
                "mark_",
                "merge_",
                "replace_",
                "update_",
                "upsert_",
            ),
        ),
        http_timeout_calls=symbols(
            "http_timeout_calls",
            (
                "aiohttp.ClientSession",
                "httpx.AsyncClient",
                "httpx.Client",
                "requests.delete",
                "requests.get",
                "requests.head",
                "requests.options",
                "requests.patch",
                "requests.post",
                "requests.put",
                "requests.request",
            ),
        ),
        logged_external_calls=symbols("logged_external_calls"),
        external_call_wrappers=frozenset(symbols("external_call_wrappers")),
        entry_allowed_kinds=FrozenMap(
            (
                Role(role),
                frozenset(strings(kinds, f"boundary_extensions.entry_allowed_kinds.{role}")),
            )
            for role, kinds in table(
                values.get("entry_allowed_kinds", {}),
                "boundary_extensions.entry_allowed_kinds",
            ).items()
        ),
    )


def load_security_policy(root: dict[str, object]) -> SecurityPolicy:
    values = table(root.get("security", {}), "security")
    reject_unknown(
        values,
        frozenset({"risky_symbol_prefixes", "environment_roles", "secret_roles", "token_roles"}),
        "security",
    )
    additions = strings(values.get("risky_symbol_prefixes", []), "security.risky_symbol_prefixes")

    def configured_roles(name: str, defaults: set[Role]) -> frozenset[Role]:
        additions = {Role(value) for value in strings(values.get(name, []), f"security.{name}")}
        return frozenset(defaults | additions)

    return SecurityPolicy(
        allowed_roles=FrozenMap(
            (
                (
                    Effect.SECURITY_ENVIRONMENT,
                    configured_roles(
                        "environment_roles", {Role("configuration"), Role("bootstrap")}
                    ),
                ),
                (
                    Effect.SECURITY_SECRET,
                    configured_roles(
                        "secret_roles",
                        {Role("configuration"), Role("bootstrap"), Role("adapter")},
                    ),
                ),
                (
                    Effect.SECURITY_TOKEN,
                    configured_roles("token_roles", {Role("security"), Role("adapter")}),
                ),
            )
        ),
        risky_symbol_prefixes=tuple(sorted(set(_RISKY_PREFIXES).union(additions))),
    )
