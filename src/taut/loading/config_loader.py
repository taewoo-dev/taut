from __future__ import annotations

from pathlib import Path

from taut.configuration.catalog import AccessPath, CatalogEntry, Effect, EffectCatalog
from taut.configuration.effective_policy import (
    BoundaryPolicy,
    EffectivePolicy,
    ImportBoundary,
    SecurityPolicy,
)
from taut.configuration.manifest import (
    ProjectManifest,
    Role,
    RoleMatcher,
    Zone,
    ZoneMatcher,
)
from taut.configuration.model import ProjectConfiguration
from taut.configuration.rule_standard import BUILTIN_RULE_LEVELS
from taut.domain.evaluations import RuleLevel, RuleSetting
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, RuleId, SymbolId
from taut.domain.location import ConfigLocation, ConfigPath, ProjectPath
from taut.domain.provider_ids import BUILTIN_BACKEND_PROVIDER_IDS
from taut.loading.boundary_extension_schema import BOUNDARY_EXTENSION_KEYS
from taut.loading.builtin_catalog import builtin_catalog_entries
from taut.loading.code_conventions import load_code_conventions
from taut.loading.config_values import ensure_unique as _ensure_unique
from taut.loading.config_values import integer as _integer
from taut.loading.config_values import reject_unknown as _reject_unknown
from taut.loading.config_values import string as _string
from taut.loading.config_values import strings as _strings
from taut.loading.config_values import table as _table
from taut.loading.config_values import table_list as _table_list
from taut.loading.configuration_document import (
    PYPROJECT_CONFIG_PATH,
    read_configuration_document,
)
from taut.loading.default_configuration import (
    default_project_configuration as default_project_configuration,
)
from taut.loading.errors import PolicyConfigError

DEFAULT_CONFIG_PATH = PYPROJECT_CONFIG_PATH
_ZONES = frozenset({"prod", "test", "migration", "script"})
_ROOT_KEYS = frozenset(
    {
        "schema_version",
        "packs",
        "providers",
        "project",
        "roles",
        "zones",
        "effects",
        "rules",
        "architecture",
        "transaction",
        "boundaries",
        "size",
        "boundary_extensions",
        "code_conventions",
        "security",
    }
)
_RISKY_PREFIXES = (
    "httpx.AsyncClient.",
    "httpx.Client.",
    "requests.",
    "subprocess.",
)


def load_project_configuration(
    project_root: Path,
    config_path: ConfigPath | None = None,
) -> ProjectConfiguration:
    try:
        return _load_project_configuration(project_root, config_path)
    except ValueError as error:
        raise PolicyConfigError(f"invalid configuration value: {error}") from error


def _load_project_configuration(
    project_root: Path,
    config_path: ConfigPath | None,
) -> ProjectConfiguration:
    document = read_configuration_document(project_root, config_path)
    root = document.root
    _reject_unknown(root, _ROOT_KEYS, "config")
    version = root.get("schema_version")
    if version != 3:
        raise PolicyConfigError("schema_version must be 3; run 'taut config migrate' first")

    packs = _strings(root.get("packs", ["taut.backend"]), "packs")
    providers = _strings(root.get("providers", list(BUILTIN_BACKEND_PROVIDER_IDS)), "providers")

    location = ConfigLocation(document.path)
    project = _table(root.get("project", {}), "project")
    _reject_unknown(
        project,
        frozenset({"include", "exclude", "source_roots", "default_zone"}),
        "project",
    )
    include = _strings(project.get("include", ["*.py", "**/*.py"]), "project.include")
    exclude = _strings(
        project.get("exclude", [".venv/**", "**/__pycache__/**", "build/**", "dist/**"]),
        "project.exclude",
    )
    source_roots = tuple(
        ProjectPath(value)
        for value in _strings(project.get("source_roots", ["."]), "project.source_roots")
    )
    default_zone = Zone(_string(project.get("default_zone", "prod"), "project.default_zone"))
    if default_zone.value not in _ZONES:
        raise PolicyConfigError(f"unknown project.default_zone: {default_zone.value}")

    roles = _load_roles(root, location)
    zones = _load_zones(root, location)
    catalog = _load_catalog(root)
    policy = _load_policy(root, strict=document.strict)
    manifest = ProjectManifest(roles, zones, default_zone, location)
    _validate_manifest_policy(manifest, policy)
    return ProjectConfiguration(
        include,
        exclude,
        source_roots,
        manifest,
        catalog,
        policy,
        schema_version=3,
        packs=packs,
        providers=providers,
    )


def _load_roles(root: dict[str, object], location: ConfigLocation) -> tuple[RoleMatcher, ...]:
    values: list[RoleMatcher] = []
    for item in _table_list(root.get("roles", []), "roles"):
        _reject_unknown(
            item,
            frozenset({"name", "patterns", "include", "exclude", "priority"}),
            "roles",
        )
        include_value = item.get("include", item.get("patterns"))
        if "include" in item and "patterns" in item:
            raise PolicyConfigError("roles cannot define both include and patterns")
        values.append(
            RoleMatcher(
                Role(_string(item.get("name"), "roles.name")),
                _strings(include_value, "roles.include"),
                location,
                _strings(item.get("exclude", []), "roles.exclude"),
                _integer(item.get("priority", 0), "roles.priority"),
            )
        )
    _ensure_unique((matcher.role.value for matcher in values), "role")
    return tuple(values)


def _load_zones(root: dict[str, object], location: ConfigLocation) -> tuple[ZoneMatcher, ...]:
    values: list[ZoneMatcher] = []
    for item in _table_list(root.get("zones", []), "zones"):
        _reject_unknown(item, frozenset({"name", "patterns"}), "zones")
        zone = Zone(_string(item.get("name"), "zones.name"))
        if zone.value not in _ZONES:
            raise PolicyConfigError(f"unknown zone: {zone.value}")
        values.append(ZoneMatcher(zone, _strings(item.get("patterns"), "zones.patterns"), location))
    _ensure_unique((matcher.zone.value for matcher in values), "zone")
    return tuple(values)


def _load_catalog(root: dict[str, object]) -> EffectCatalog:
    entries = {entry.symbol: entry for entry in builtin_catalog_entries()}
    for item in _table_list(root.get("effects", []), "effects"):
        _reject_unknown(item, frozenset({"symbol", "effects", "access"}), "effects")
        symbol = SymbolId(_string(item.get("symbol"), "effects.symbol"))
        try:
            effects = frozenset(
                Effect(value) for value in _strings(item.get("effects"), "effects.effects")
            )
            access_path = AccessPath(_string(item.get("access", "direct"), "effects.access"))
        except ValueError as error:
            raise PolicyConfigError(
                f"invalid effect catalog entry for {symbol.value}: {error}"
            ) from error
        entry = CatalogEntry(symbol, effects, access_path)
        previous = entries.get(symbol)
        if previous is not None and previous != entry:
            raise PolicyConfigError(f"cannot override built-in effect: {symbol.value}")
        entries[symbol] = entry
    return EffectCatalog(FrozenMap(entries))


def _load_policy(root: dict[str, object], *, strict: bool) -> EffectivePolicy:
    rule_table = _table(root.get("rules", {}), "rules")
    known = {rule_id.value for rule_id in BUILTIN_RULE_LEVELS}
    unknown = set(rule_table).difference(known)
    if unknown:
        raise PolicyConfigError(f"unknown rules: {', '.join(sorted(unknown))}")
    settings: list[tuple[RuleId, RuleSetting]] = []
    for rule_id, level in BUILTIN_RULE_LEVELS.items():
        configured = rule_table.get(rule_id.value)
        if configured is not None:
            value = _string(configured, f"rules.{rule_id.value}")
            if value != level.value:
                raise PolicyConfigError(f"{rule_id.value} is fixed at {level.value}")
        effective_level = level if strict or level is RuleLevel.ADVISORY else RuleLevel.ADVISORY
        settings.append((rule_id, RuleSetting(effective_level, FrozenMap())))

    architecture = _table(root.get("architecture", {}), "architecture")
    _reject_unknown(architecture, frozenset({"allow"}), "architecture")
    allow_table = _table(architecture.get("allow", {}), "architecture.allow")
    allowed_imports = FrozenMap(
        (
            Role(source),
            frozenset(Role(target) for target in _strings(targets, f"architecture.allow.{source}")),
        )
        for source, targets in allow_table.items()
    )

    transaction = _table(root.get("transaction", {}), "transaction")
    _reject_unknown(
        transaction,
        frozenset({"owner_roles", "session_providers"}),
        "transaction",
    )
    owners = frozenset(
        Role(value)
        for value in _strings(transaction.get("owner_roles", []), "transaction.owner_roles")
    )
    session_providers = frozenset(
        SymbolId(value)
        for value in _strings(
            transaction.get("session_providers", []),
            "transaction.session_providers",
        )
    )
    if session_providers and not owners:
        raise PolicyConfigError("transaction.session_providers requires owner_roles")

    boundaries = _load_import_boundaries(root)
    size = _table(root.get("size", {}), "size")
    _reject_unknown(size, frozenset({"default_max_lines", "role_max_lines"}), "size")
    default_max_lines = _integer(size.get("default_max_lines", 700), "size.default_max_lines")
    role_max_table = _table(size.get("role_max_lines", {}), "size.role_max_lines")
    max_lines_by_role = FrozenMap(
        (Role(role), _integer(value, f"size.role_max_lines.{role}"))
        for role, value in role_max_table.items()
    )
    return EffectivePolicy(
        rules=FrozenMap(settings),
        allowed_imports=allowed_imports,
        transaction_owner_roles=owners,
        transaction_session_providers=session_providers,
        import_boundaries=boundaries,
        default_max_lines=default_max_lines,
        max_lines_by_role=max_lines_by_role,
        boundaries=_load_boundary_extensions(root),
        code=load_code_conventions(root.get("code_conventions", {})),
        security=_load_security_policy(root),
    )


def _load_import_boundaries(root: dict[str, object]) -> tuple[ImportBoundary, ...]:
    boundaries: list[ImportBoundary] = []
    for item in _table_list(root.get("boundaries", []), "boundaries"):
        _reject_unknown(
            item,
            frozenset({"name", "roles", "forbidden_imports", "forbidden_calls"}),
            "boundaries",
        )
        name = _string(item.get("name"), "boundaries.name")
        boundaries.append(
            ImportBoundary(
                name=name,
                roles=frozenset(
                    Role(value) for value in _strings(item.get("roles"), f"boundaries.{name}.roles")
                ),
                forbidden_imports=tuple(
                    sorted(
                        ModuleId(value)
                        for value in _strings(
                            item.get("forbidden_imports", []),
                            f"boundaries.{name}.forbidden_imports",
                        )
                    )
                ),
                forbidden_calls=tuple(
                    sorted(
                        _strings(
                            item.get("forbidden_calls", []),
                            f"boundaries.{name}.forbidden_calls",
                        )
                    )
                ),
            )
        )
    _ensure_unique((boundary.name for boundary in boundaries), "import boundary")
    return tuple(sorted(boundaries, key=lambda boundary: boundary.name))


def _load_boundary_extensions(root: dict[str, object]) -> BoundaryPolicy:
    table = _table(root.get("boundary_extensions", {}), "boundary_extensions")
    _reject_unknown(table, BOUNDARY_EXTENSION_KEYS, "boundary_extensions")

    def roles(name: str, defaults: tuple[str, ...] = ()) -> frozenset[Role]:
        additions = _strings(table.get(name, []), f"boundary_extensions.{name}")
        return frozenset(Role(value) for value in set(defaults).union(additions))

    def modules(name: str, defaults: tuple[str, ...] = ()) -> tuple[ModuleId, ...]:
        additions = _strings(table.get(name, []), f"boundary_extensions.{name}")
        return tuple(sorted(ModuleId(value) for value in set(defaults).union(additions)))

    def symbols(name: str, defaults: tuple[str, ...] = ()) -> tuple[SymbolId, ...]:
        additions = _strings(table.get(name, []), f"boundary_extensions.{name}")
        return tuple(sorted(SymbolId(value) for value in set(defaults).union(additions)))

    def names(name: str, defaults: tuple[str, ...] = ()) -> tuple[str, ...]:
        additions = _strings(table.get(name, []), f"boundary_extensions.{name}")
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
        configuration_roles=roles("configuration_roles", ("configuration",)),
        raw_query_roles=roles("raw_query_roles", ("raw_query",)),
        external_modules=modules(
            "external_modules", ("anthropic", "boto3", "httpx", "openai", "requests")
        ),
        database_modules=modules("database_modules", ("sqlalchemy",)),
        transport_modules=modules("transport_modules", ("fastapi", "starlette")),
        contract_forbidden_modules=modules(
            "contract_forbidden_modules",
            ("anthropic", "fastapi", "httpx", "openai", "sqlalchemy"),
        ),
        adapter_forbidden_modules=modules("adapter_forbidden_modules", ("sqlalchemy",)),
        adapter_forbidden_calls=symbols(
            "adapter_forbidden_calls",
            (
                "sqlalchemy.ext.asyncio.AsyncSession.add",
                "sqlalchemy.ext.asyncio.AsyncSession.commit",
                "sqlalchemy.ext.asyncio.AsyncSession.execute",
                "sqlalchemy.ext.asyncio.AsyncSession.flush",
                "sqlalchemy.ext.asyncio.AsyncSession.rollback",
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
            ),
        ),
        transport_exception_calls=symbols(
            "transport_exception_calls",
            ("fastapi.HTTPException", "starlette.exceptions.HTTPException"),
        ),
        dependency_injection_calls=symbols(
            "dependency_injection_calls",
            ("fastapi.Depends", "fastapi.params.Depends"),
        ),
        external_client_constructors=symbols(
            "external_client_constructors",
            (
                "httpx.AsyncClient",
                "httpx.Client",
                "openai.AsyncOpenAI",
                "openai.OpenAI",
            ),
        ),
        adapter_implementation_symbols=frozenset(symbols("adapter_implementation_symbols")),
        adapter_implementation_suffixes=names(
            "adapter_implementation_suffixes",
            ("Adapter", "Client", "Gateway", "Harness"),
        ),
        settings_constructors=symbols("settings_constructors"),
        session_type_symbols=symbols(
            "session_type_symbols",
            (
                "sqlalchemy.ext.asyncio.AsyncSession",
                "sqlalchemy.orm.Session",
            ),
        ),
        raw_sql_calls=symbols(
            "raw_sql_calls",
            ("sqlalchemy.sql.expression.text", "sqlalchemy.text"),
        ),
        raw_query_wrappers=frozenset(symbols("raw_query_wrappers")),
        schema_sql_roles=roles("schema_sql_roles", ("model",)),
        schema_sql_argument_names=names(
            "schema_sql_argument_names",
            ("postgresql_where", "server_default", "sqlite_where"),
        ),
        raw_sql_execution_methods=names(
            "raw_sql_execution_methods",
            ("exec_driver_sql", "execute"),
        ),
        database_owner_names=names("database_owner_names", ("conn", "connection", "db", "session")),
        database_primitive_methods=names(
            "database_primitive_methods",
            ("add", "add_all", "delete", "execute", "flush", "get", "merge"),
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
        http_timeout_calls=symbols("http_timeout_calls", ("httpx.AsyncClient", "httpx.Client")),
        logged_external_calls=symbols("logged_external_calls"),
        external_call_wrappers=frozenset(symbols("external_call_wrappers")),
    )


def _load_security_policy(root: dict[str, object]) -> SecurityPolicy:
    table = _table(root.get("security", {}), "security")
    _reject_unknown(table, frozenset({"risky_symbol_prefixes"}), "security")
    additions = _strings(table.get("risky_symbol_prefixes", []), "security.risky_symbol_prefixes")
    return SecurityPolicy(
        allowed_roles=FrozenMap(
            (
                (
                    Effect.SECURITY_ENVIRONMENT,
                    frozenset({Role("configuration"), Role("bootstrap")}),
                ),
                (
                    Effect.SECURITY_SECRET,
                    frozenset({Role("configuration"), Role("bootstrap"), Role("adapter")}),
                ),
                (Effect.SECURITY_TOKEN, frozenset({Role("security"), Role("adapter")})),
            )
        ),
        risky_symbol_prefixes=tuple(sorted(set(_RISKY_PREFIXES).union(additions))),
    )


def _validate_manifest_policy(manifest: ProjectManifest, policy: EffectivePolicy) -> None:
    declared = {matcher.role for matcher in manifest.roles}
    missing = declared.difference(policy.allowed_imports)
    if missing:
        names = ", ".join(sorted(role.value for role in missing))
        raise PolicyConfigError(f"architecture.allow is missing roles: {names}")
    unknown_sources = set(policy.allowed_imports).difference(declared)
    unknown_targets = {
        role for roles in policy.allowed_imports.values() for role in roles
    }.difference(declared)
    unknown = unknown_sources.union(unknown_targets)
    if unknown:
        names = ", ".join(sorted(role.value for role in unknown))
        raise PolicyConfigError(f"architecture.allow contains undeclared roles: {names}")
