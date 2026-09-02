from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from taut.configuration.catalog import Effect
from taut.configuration.manifest import Role, Zone
from taut.domain.evaluations import RuleSetting
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, RuleId, SymbolId
from taut.domain.location import ProjectPath

_APPROVAL_KINDS = frozenset(
    {"allow", "entrypoint", "factory", "lazy_import", "managed", "participant", "security_wrapper"}
)


@dataclass(frozen=True)
class ImportBoundary:
    name: str
    roles: frozenset[Role]
    forbidden_imports: tuple[ModuleId, ...] = ()
    forbidden_calls: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("import boundary name cannot be empty")
        if not self.roles:
            raise ValueError("import boundary requires at least one role")
        if not self.forbidden_imports and not self.forbidden_calls:
            raise ValueError("boundary requires at least one forbidden import or call")
        if len(self.forbidden_imports) != len(set(self.forbidden_imports)):
            raise ValueError("import boundary contains duplicate forbidden imports")
        if self.forbidden_imports != tuple(sorted(self.forbidden_imports)):
            raise ValueError("import boundary forbidden imports must be sorted")
        if self.forbidden_calls != tuple(sorted(set(self.forbidden_calls))):
            raise ValueError("boundary forbidden calls must be unique and sorted")


@dataclass(frozen=True)
class BoundaryPolicy:
    entry_roles: frozenset[Role] = frozenset()
    service_roles: frozenset[Role] = frozenset()
    contract_roles: frozenset[Role] = frozenset()
    adapter_roles: frozenset[Role] = frozenset()
    query_roles: frozenset[Role] = frozenset()
    model_roles: frozenset[Role] = frozenset()
    bootstrap_roles: frozenset[Role] = frozenset()
    implementation_construction_roles: frozenset[Role] = frozenset()
    scoped_construction_roles: frozenset[Role] = frozenset()
    configuration_roles: frozenset[Role] = frozenset()
    dependency_registration_roles: frozenset[Role] = frozenset()
    raw_query_roles: frozenset[Role] = frozenset()
    external_modules: tuple[ModuleId, ...] = ()
    database_modules: tuple[ModuleId, ...] = ()
    transport_modules: tuple[ModuleId, ...] = ()
    contract_forbidden_modules: tuple[ModuleId, ...] = ()
    adapter_forbidden_modules: tuple[ModuleId, ...] = ()
    adapter_forbidden_calls: tuple[SymbolId, ...] = ()
    database_statement_calls: tuple[SymbolId, ...] = ()
    transport_exception_calls: tuple[SymbolId, ...] = ()
    dependency_injection_calls: tuple[SymbolId, ...] = ()
    external_client_constructors: tuple[SymbolId, ...] = ()
    adapter_implementation_symbols: frozenset[SymbolId] = frozenset()
    adapter_implementation_suffixes: tuple[str, ...] = ()
    settings_constructors: tuple[SymbolId, ...] = ()
    session_type_symbols: tuple[SymbolId, ...] = ()
    raw_sql_calls: tuple[SymbolId, ...] = ()
    raw_query_wrappers: frozenset[SymbolId] = frozenset()
    schema_sql_roles: frozenset[Role] = frozenset()
    schema_sql_argument_names: tuple[str, ...] = ()
    schema_sql_parent_calls: tuple[SymbolId, ...] = ()
    raw_sql_execution_methods: tuple[str, ...] = ()
    database_owner_names: tuple[str, ...] = ()
    database_primitive_methods: tuple[str, ...] = ()
    query_write_method_prefixes: tuple[str, ...] = ()
    http_timeout_calls: tuple[SymbolId, ...] = ()
    logged_external_calls: tuple[SymbolId, ...] = ()
    external_call_wrappers: frozenset[SymbolId] = frozenset()
    entry_allowed_kinds: FrozenMap[Role, frozenset[str]] = field(
        default_factory=lambda: FrozenMap[Role, frozenset[str]]()
    )

    def __post_init__(self) -> None:
        module_fields: tuple[tuple[ModuleId, ...], ...] = (
            self.external_modules,
            self.database_modules,
            self.transport_modules,
            self.contract_forbidden_modules,
            self.adapter_forbidden_modules,
        )
        symbol_fields: tuple[tuple[SymbolId, ...], ...] = (
            self.adapter_forbidden_calls,
            self.database_statement_calls,
            self.transport_exception_calls,
            self.dependency_injection_calls,
            self.external_client_constructors,
            self.settings_constructors,
            self.session_type_symbols,
            self.raw_sql_calls,
            self.http_timeout_calls,
            self.logged_external_calls,
            self.schema_sql_parent_calls,
        )
        string_fields = (
            self.database_owner_names,
            self.database_primitive_methods,
            self.query_write_method_prefixes,
            self.adapter_implementation_suffixes,
            self.schema_sql_argument_names,
            self.raw_sql_execution_methods,
        )
        if any(values != tuple(sorted(set(values))) for values in module_fields):
            raise ValueError("boundary policy lists must be unique and sorted")
        if any(values != tuple(sorted(set(values))) for values in symbol_fields):
            raise ValueError("boundary policy lists must be unique and sorted")
        if any(values != tuple(sorted(set(values))) for values in string_fields):
            raise ValueError("boundary policy names must be unique and sorted")
        if any(not value.strip() for values in string_fields for value in values):
            raise ValueError("boundary policy names cannot be empty")
        allowed_entry_kinds = {"database", "external", "session", "transport_exception"}
        if any(
            not kinds.issubset(allowed_entry_kinds) for kinds in self.entry_allowed_kinds.values()
        ):
            raise ValueError("entry allowance contains an unknown boundary kind")


@dataclass(frozen=True, order=True)
class PolicyApproval:
    rule_id: RuleId
    symbol: SymbolId
    reason: str
    target: str | None = None
    kind: str = "allow"
    zones: frozenset[Zone] = frozenset(
        {Zone("prod"), Zone("test"), Zone("migration"), Zone("script")}
    )

    def __post_init__(self) -> None:
        if not self.reason.strip():
            raise ValueError("policy approval reason cannot be empty")
        if self.target is not None and not self.target.strip():
            raise ValueError("policy approval target cannot be empty")
        if not self.kind or not self.kind.replace("_", "").isalnum() or not self.kind.islower():
            raise ValueError("policy approval kind must be a lowercase name")
        if self.kind not in _APPROVAL_KINDS:
            raise ValueError(f"unknown policy approval kind: {self.kind}")
        if self.kind in {"managed", "participant"} and self.rule_id != RuleId("SESSION003"):
            raise ValueError(f"approval kind {self.kind} is only valid for SESSION003")
        if not self.zones:
            raise ValueError("policy approval requires at least one zone")

    @property
    def key(self) -> str:
        target = self.target or "*"
        zones = ",".join(sorted(zone.value for zone in self.zones))
        return f"{self.rule_id.value}:{self.symbol.value}:{target}:{self.kind}:{zones}"


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
    dto_name_suffixes: tuple[str, ...] = ("Data", "Result", "Row")
    test_root_paths: tuple[ProjectPath, ...] = (ProjectPath("tests"),)
    raw_test_http_calls: tuple[SymbolId, ...] = ()
    raw_test_http_client_constructors: tuple[SymbolId, ...] = ()
    test_http_fixture_roles: frozenset[Role] = frozenset()

    def __post_init__(self) -> None:
        if self.shared_enum_modules != tuple(sorted(set(self.shared_enum_modules))):
            raise ValueError("shared enum modules must be unique and sorted")
        if self.dto_name_suffixes != tuple(sorted(set(self.dto_name_suffixes))):
            raise ValueError("DTO name suffixes must be unique and sorted")
        if any(not suffix.strip() for suffix in self.dto_name_suffixes):
            raise ValueError("DTO name suffix cannot be empty")
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


@dataclass(frozen=True)
class SecurityPolicy:
    allowed_roles: FrozenMap[Effect, frozenset[Role]] = field(
        default_factory=lambda: FrozenMap[Effect, frozenset[Role]]()
    )
    risky_symbol_prefixes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.risky_symbol_prefixes != tuple(sorted(set(self.risky_symbol_prefixes))):
            raise ValueError("risky symbol prefixes must be unique and sorted")
        if any(not prefix.strip() for prefix in self.risky_symbol_prefixes):
            raise ValueError("risky symbol prefix cannot be empty")
        security_effects = {
            Effect.SECURITY_ENVIRONMENT,
            Effect.SECURITY_SECRET,
            Effect.SECURITY_TOKEN,
        }
        if not set(self.allowed_roles).issubset(security_effects):
            raise ValueError("security role mapping contains a non-security effect")


@dataclass(frozen=True)
class EffectivePolicy:
    rules: FrozenMap[RuleId, RuleSetting]
    allowed_imports: FrozenMap[Role, frozenset[Role]]
    transaction_owner_roles: frozenset[Role]
    transaction_participant_roles: frozenset[Role] = frozenset()
    transaction_session_providers: frozenset[SymbolId] = frozenset()
    transaction_provider_item_types: FrozenMap[SymbolId, SymbolId] = field(
        default_factory=lambda: FrozenMap[SymbolId, SymbolId]()
    )
    rule_zones: FrozenMap[RuleId, frozenset[Zone]] = field(
        default_factory=lambda: FrozenMap[RuleId, frozenset[Zone]]()
    )
    approvals: tuple[PolicyApproval, ...] = ()
    import_boundaries: tuple[ImportBoundary, ...] = ()
    default_max_lines: int = 700
    max_lines_by_role: FrozenMap[Role, int] = field(default_factory=lambda: FrozenMap[Role, int]())
    boundaries: BoundaryPolicy = field(default_factory=BoundaryPolicy)
    code: CodeConventionPolicy = field(default_factory=CodeConventionPolicy)
    security: SecurityPolicy = field(default_factory=SecurityPolicy)

    def __post_init__(self) -> None:
        if self.default_max_lines < 1:
            raise ValueError("default maximum lines must be positive")
        if any(
            not 1 <= maximum <= self.default_max_lines
            for maximum in self.max_lines_by_role.values()
        ):
            raise ValueError("role maximum lines must be between 1 and the configured default")
        if not set(self.rule_zones).issubset(self.rules):
            raise ValueError("rule zone mapping contains an unknown rule")
        if any(not zones for zones in self.rule_zones.values()):
            raise ValueError("rule zone mapping cannot be empty")
        if self.approvals != tuple(sorted(self.approvals, key=lambda item: item.key)):
            raise ValueError("policy approvals must be sorted")
        if len({approval.key for approval in self.approvals}) != len(self.approvals):
            raise ValueError("policy approvals must be unique")
        if not set(self.transaction_provider_item_types).issubset(
            self.transaction_session_providers
        ):
            raise ValueError("transaction provider item types require a configured provider")

    def setting(self, rule_id: RuleId) -> RuleSetting:
        return self.rules[rule_id]

    def approval_for(
        self,
        rule_id: RuleId,
        symbol: SymbolId,
        zone: Zone,
        *,
        target: str | None = None,
        kind: str | None = None,
    ) -> PolicyApproval | None:
        return next(
            (
                approval
                for approval in self.approvals
                if approval.rule_id == rule_id
                and approval.symbol == symbol
                and zone in approval.zones
                and (kind is None or approval.kind == kind)
                and (approval.target is None or approval.target == target)
            ),
            None,
        )

    def digest(self) -> str:
        payload = {
            "rules": [
                {
                    "id": rule_id.value,
                    "level": setting.level.value,
                    "parameters": list(setting.parameters.items()),
                }
                for rule_id, setting in self.rules.items()
            ],
            "allowed_imports": [
                (source.value, sorted(target.value for target in targets))
                for source, targets in self.allowed_imports.items()
            ],
            "transaction_owner_roles": sorted(role.value for role in self.transaction_owner_roles),
            "transaction_participant_roles": sorted(
                role.value for role in self.transaction_participant_roles
            ),
            "transaction_session_providers": sorted(
                symbol.value for symbol in self.transaction_session_providers
            ),
            "transaction_provider_item_types": [
                (provider.value, item_type.value)
                for provider, item_type in self.transaction_provider_item_types.items()
            ],
            "rule_zones": [
                (rule_id.value, sorted(zone.value for zone in zones))
                for rule_id, zones in self.rule_zones.items()
            ],
            "approvals": [
                {
                    "rule": approval.rule_id.value,
                    "symbol": approval.symbol.value,
                    "target": approval.target,
                    "kind": approval.kind,
                    "zones": sorted(zone.value for zone in approval.zones),
                    "reason": approval.reason,
                }
                for approval in self.approvals
            ],
            "import_boundaries": [
                {
                    "name": boundary.name,
                    "roles": sorted(role.value for role in boundary.roles),
                    "forbidden_imports": [module.value for module in boundary.forbidden_imports],
                    "forbidden_calls": list(boundary.forbidden_calls),
                }
                for boundary in self.import_boundaries
            ],
            "default_max_lines": self.default_max_lines,
            "max_lines_by_role": [
                (role.value, maximum) for role, maximum in self.max_lines_by_role.items()
            ],
            "boundaries": {
                "entry_roles": sorted(role.value for role in self.boundaries.entry_roles),
                "service_roles": sorted(role.value for role in self.boundaries.service_roles),
                "contract_roles": sorted(role.value for role in self.boundaries.contract_roles),
                "adapter_roles": sorted(role.value for role in self.boundaries.adapter_roles),
                "query_roles": sorted(role.value for role in self.boundaries.query_roles),
                "model_roles": sorted(role.value for role in self.boundaries.model_roles),
                "bootstrap_roles": sorted(role.value for role in self.boundaries.bootstrap_roles),
                "implementation_construction_roles": sorted(
                    role.value for role in self.boundaries.implementation_construction_roles
                ),
                "scoped_construction_roles": sorted(
                    role.value for role in self.boundaries.scoped_construction_roles
                ),
                "configuration_roles": sorted(
                    role.value for role in self.boundaries.configuration_roles
                ),
                "dependency_registration_roles": sorted(
                    role.value for role in self.boundaries.dependency_registration_roles
                ),
                "raw_query_roles": sorted(role.value for role in self.boundaries.raw_query_roles),
                "external_modules": [item.value for item in self.boundaries.external_modules],
                "database_modules": [item.value for item in self.boundaries.database_modules],
                "transport_modules": [item.value for item in self.boundaries.transport_modules],
                "contract_forbidden_modules": [
                    item.value for item in self.boundaries.contract_forbidden_modules
                ],
                "adapter_forbidden_modules": [
                    item.value for item in self.boundaries.adapter_forbidden_modules
                ],
                "adapter_forbidden_calls": [
                    item.value for item in self.boundaries.adapter_forbidden_calls
                ],
                "database_statement_calls": [
                    item.value for item in self.boundaries.database_statement_calls
                ],
                "transport_exception_calls": [
                    item.value for item in self.boundaries.transport_exception_calls
                ],
                "dependency_injection_calls": [
                    item.value for item in self.boundaries.dependency_injection_calls
                ],
                "external_client_constructors": [
                    item.value for item in self.boundaries.external_client_constructors
                ],
                "adapter_implementation_symbols": sorted(
                    item.value for item in self.boundaries.adapter_implementation_symbols
                ),
                "adapter_implementation_suffixes": list(
                    self.boundaries.adapter_implementation_suffixes
                ),
                "settings_constructors": [
                    item.value for item in self.boundaries.settings_constructors
                ],
                "session_type_symbols": [
                    item.value for item in self.boundaries.session_type_symbols
                ],
                "raw_sql_calls": [item.value for item in self.boundaries.raw_sql_calls],
                "raw_query_wrappers": sorted(
                    item.value for item in self.boundaries.raw_query_wrappers
                ),
                "schema_sql_roles": sorted(role.value for role in self.boundaries.schema_sql_roles),
                "schema_sql_argument_names": list(self.boundaries.schema_sql_argument_names),
                "schema_sql_parent_calls": [
                    item.value for item in self.boundaries.schema_sql_parent_calls
                ],
                "raw_sql_execution_methods": list(self.boundaries.raw_sql_execution_methods),
                "database_owner_names": list(self.boundaries.database_owner_names),
                "database_primitive_methods": list(self.boundaries.database_primitive_methods),
                "query_write_method_prefixes": list(self.boundaries.query_write_method_prefixes),
                "http_timeout_calls": [item.value for item in self.boundaries.http_timeout_calls],
                "logged_external_calls": [
                    item.value for item in self.boundaries.logged_external_calls
                ],
                "external_call_wrappers": sorted(
                    item.value for item in self.boundaries.external_call_wrappers
                ),
                "entry_allowed_kinds": [
                    (role.value, sorted(kinds))
                    for role, kinds in self.boundaries.entry_allowed_kinds.items()
                ],
            },
            "code_conventions": {
                "dto_roles": sorted(role.value for role in self.code.dto_roles),
                "schema_roles": sorted(role.value for role in self.code.schema_roles),
                "router_roles": sorted(role.value for role in self.code.router_roles),
                "service_roles": sorted(role.value for role in self.code.service_roles),
                "model_roles": sorted(role.value for role in self.code.model_roles),
                "snapshot_roles": sorted(role.value for role in self.code.snapshot_roles),
                "request_config_symbols": sorted(
                    symbol.value for symbol in self.code.request_config_symbols
                ),
                "response_config_symbols": sorted(
                    symbol.value for symbol in self.code.response_config_symbols
                ),
                "shared_enum_modules": [item.value for item in self.code.shared_enum_modules],
                "uppercase_enum_exceptions": sorted(
                    symbol.value for symbol in self.code.uppercase_enum_exceptions
                ),
                "non_str_enum_exceptions": sorted(
                    symbol.value for symbol in self.code.non_str_enum_exceptions
                ),
                "native_enum_false_exceptions": sorted(
                    symbol.value for symbol in self.code.native_enum_false_exceptions
                ),
                "native_enum_no_constraint_exceptions": sorted(
                    symbol.value for symbol in self.code.native_enum_no_constraint_exceptions
                ),
                "generic_schema_bases": sorted(
                    symbol.value for symbol in self.code.generic_schema_bases
                ),
                "forbidden_runtime_calls": list(self.code.forbidden_runtime_calls),
                "exception_base_symbols": sorted(
                    symbol.value for symbol in self.code.exception_base_symbols
                ),
                "abstract_exception_symbols": sorted(
                    symbol.value for symbol in self.code.abstract_exception_symbols
                ),
                "error_code_enum_symbols": sorted(
                    symbol.value for symbol in self.code.error_code_enum_symbols
                ),
                "reserved_error_code_symbols": sorted(
                    symbol.value for symbol in self.code.reserved_error_code_symbols
                ),
                "dto_name_suffixes": list(self.code.dto_name_suffixes),
                "test_root_paths": [path.value for path in self.code.test_root_paths],
                "raw_test_http_calls": [symbol.value for symbol in self.code.raw_test_http_calls],
                "raw_test_http_client_constructors": [
                    symbol.value for symbol in self.code.raw_test_http_client_constructors
                ],
                "test_http_fixture_roles": sorted(
                    role.value for role in self.code.test_http_fixture_roles
                ),
            },
            "security": {
                "allowed_roles": [
                    (effect.value, sorted(role.value for role in roles))
                    for effect, roles in self.security.allowed_roles.items()
                ],
                "risky_symbol_prefixes": list(self.security.risky_symbol_prefixes),
            },
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()
