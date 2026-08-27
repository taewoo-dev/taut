from __future__ import annotations

from pathlib import Path

import pytest
from tests.utils.builders import analyze, make_context, make_source
from tests.utils.config import assurance_toml

from taut.configuration.catalog import (
    AccessPath,
    CatalogEntry,
    Effect,
    EffectCatalog,
    EffectResolutionState,
    EffectResolver,
)
from taut.configuration.manifest import (
    ProjectManifest,
    Role,
    RoleMatcher,
    Zone,
    ZoneMatcher,
)
from taut.configuration.validation import validate_classification_for_policy
from taut.domain.evaluations import RuleLevel
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, RuleId, SymbolId
from taut.domain.location import ConfigLocation, ProjectPath
from taut.loading.config_loader import (
    default_project_configuration,
    load_project_configuration,
)
from taut.loading.errors import PolicyConfigError

_VALID = f"""
schema_version = 4
packs = ['taut.backend']
[project]
include = ["src/*.py", "src/**/*.py"]
source_roots = ["src"]
default_zone = "prod"

[[roles]]
name = "service"
patterns = ["src/app/**"]

[[effects]]
symbol = "app.clock.utc_now"
effects = ["time.now"]
access = "approved_wrapper"

[architecture.allow]
service = ["service"]

[transaction]
owner_roles = ["service"]
participant_roles = ["service"]
session_providers = ["app.database.get_async_session"]

[size]
default_max_lines = 500
[size.role_max_lines]
service = 400
{assurance_toml()}
""".strip()

_PYPROJECT_VALID = f"""
[project]
name = "sample-service"
version = "0.1.0"

[tool.taut]
strict = true
source_roots = ["src"]

[tool.taut.roles]
service = ["src/app/**"]

[tool.taut.allow]
service = ["service"]

[tool.taut.layers]
service = ["service"]

[tool.taut.external]
logged_calls = ["sample.Client"]
wrappers = ["app.external.call"]

[tool.taut.enum]
shared_modules = ["app.enums"]
non_string_exceptions = ["app.enums.NumericCode"]

{assurance_toml(pyproject=True)}
""".strip()


def _write(root: Path, content: str = _VALID) -> None:
    policy_dir = root / ".policy"
    policy_dir.mkdir()
    (policy_dir / "policy.toml").write_text(content)


def _write_pyproject(root: Path, content: str = _PYPROJECT_VALID) -> None:
    (root / "pyproject.toml").write_text(content)


def test_pyproject_configuration_uses_concise_tables_and_builtin_defaults(
    tmp_path: Path,
) -> None:
    _write_pyproject(tmp_path)

    config = load_project_configuration(tmp_path)

    assert config.manifest.source.path.value == "pyproject.toml"
    assert config.policy.default_max_lines == 700
    assert config.policy.setting(RuleId("TIME001")).level is RuleLevel.ENFORCED
    assert config.policy.boundaries.service_roles == frozenset({Role("service")})
    assert SymbolId("sample.Client") in config.policy.boundaries.logged_external_calls
    assert SymbolId("app.external.call") in config.policy.boundaries.external_call_wrappers
    assert config.policy.code.shared_enum_modules == (ModuleId("app.enums"),)
    assert config.policy.code.non_str_enum_exceptions == frozenset(
        {SymbolId("app.enums.NumericCode")}
    )


def test_pyproject_configuration_accepts_cache_and_rule_tables(tmp_path: Path) -> None:
    _write_pyproject(
        tmp_path,
        _PYPROJECT_VALID
        + """

[tool.taut.cache]
enabled = false
directory = "cache-data"

[tool.taut.rules]
TIME001 = "enforced"
""",
    )

    config = load_project_configuration(tmp_path)

    assert config.cache_enabled is False
    assert config.cache_directory == ProjectPath("cache-data")
    assert config.policy.setting(RuleId("TIME001")).level is RuleLevel.ENFORCED


def test_pyproject_loads_role_zone_and_reasoned_symbol_approvals(tmp_path: Path) -> None:
    content = (
        _PYPROJECT_VALID
        + """

[tool.taut.rule_zones]
IMPORT001 = ["prod"]
IMPORT002 = ["prod", "migration"]

[tool.taut.boundary_extensions.entry_allowed_kinds]
task = ["external"]

[tool.taut.security]
environment_roles = ["composition"]
token_roles = ["security_wrapper"]

[[tool.taut.approvals]]
rule = "SESSION003"
symbol = "app.services.notifications._persist"
target = "sqlalchemy.ext.asyncio.AsyncSession"
kind = "participant"
zones = ["prod"]
reason = "called only inside the notification transaction"
"""
    )
    _write_pyproject(tmp_path, content)

    policy = load_project_configuration(tmp_path).policy
    approval = policy.approvals[0]

    assert policy.rule_zones[RuleId("IMPORT001")] == frozenset({Zone("prod")})
    assert policy.boundaries.entry_allowed_kinds[Role("task")] == frozenset({"external"})
    assert Role("composition") in policy.security.allowed_roles[Effect.SECURITY_ENVIRONMENT]
    assert Role("security_wrapper") in policy.security.allowed_roles[Effect.SECURITY_TOKEN]
    assert approval.symbol == SymbolId("app.services.notifications._persist")
    assert approval.kind == "participant"
    assert approval.reason == "called only inside the notification transaction"


@pytest.mark.parametrize(
    "extension, message",
    [
        ("[rule_zones]\nUNKNOWN001 = ['prod']", "unknown rule_zones"),
        ("[rule_zones]\nIMPORT001 = []", "requires at least one zone"),
        ("[rule_zones]\nIMPORT001 = ['staging']", "unknown rule_zones"),
        (
            "[[approvals]]\nrule='UNKNOWN001'\nsymbol='app.x'\nreason='test'",
            "unknown approval rule",
        ),
        (
            "[[approvals]]\nrule='IMPORT001'\nsymbol='app.x'\nzones=['staging']\nreason='test'",
            "unknown approval zones",
        ),
        (
            "[[approvals]]\nrule='IMPORT001'\nsymbol='app.x'\nkind='partcipant'\nreason='test'",
            "unknown policy approval kind",
        ),
        (
            "[[approvals]]\nrule='IMPORT001'\nsymbol='app.x'\nkind='participant'\nreason='test'",
            "only valid for SESSION003",
        ),
    ],
)
def test_policy_scope_configuration_rejects_unknown_rules_and_zones(
    tmp_path: Path, extension: str, message: str
) -> None:
    _write(tmp_path, "schema_version = 4\n" + extension)

    with pytest.raises(PolicyConfigError, match=message):
        load_project_configuration(tmp_path)


def test_pyproject_non_strict_mode_reports_builtin_rules_as_advisory(tmp_path: Path) -> None:
    _write_pyproject(tmp_path, _PYPROJECT_VALID.replace("strict = true", "strict = false"))

    policy = load_project_configuration(tmp_path).policy

    assert policy.setting(RuleId("TIME001")).level is RuleLevel.ADVISORY
    assert policy.setting(RuleId("CAT001")).level is RuleLevel.ADVISORY


def test_pyproject_strict_and_max_lines_use_builtin_defaults(tmp_path: Path) -> None:
    _write_pyproject(tmp_path, _PYPROJECT_VALID.replace("strict = true\n", ""))

    policy = load_project_configuration(tmp_path).policy

    assert policy.setting(RuleId("TIME001")).level is RuleLevel.ENFORCED
    assert policy.default_max_lines == 700

    _write_pyproject(tmp_path, _PYPROJECT_VALID.replace("strict = true", "max_lines = 1200"))
    assert load_project_configuration(tmp_path).policy.default_max_lines == 1200


@pytest.mark.parametrize(
    "content",
    [
        "[tool.taut]\nstrict = 'yes'",
        "[tool.taut]\nunknown = true",
        "[tool.taut]\n[tool.taut.external]\nunknown = []",
    ],
)
def test_pyproject_configuration_rejects_invalid_or_unknown_values(
    tmp_path: Path,
    content: str,
) -> None:
    _write_pyproject(tmp_path, content)

    with pytest.raises(PolicyConfigError):
        load_project_configuration(tmp_path)


def test_load_v4_configuration_uses_backend_pack_policy(tmp_path: Path) -> None:
    _write(tmp_path)

    config = load_project_configuration(tmp_path)

    assert config.source_roots == (ProjectPath("src"),)
    assert config.policy.setting(RuleId("DTO002")).level is RuleLevel.ENFORCED
    assert config.policy.setting(RuleId("CAT001")).level is RuleLevel.ADVISORY
    assert config.policy.transaction_participant_roles == frozenset({Role("service")})
    wrapper = config.catalog.entries[SymbolId("app.clock.utc_now")]
    assert wrapper.effects == frozenset({Effect.TIME_NOW})
    assert wrapper.access_path is AccessPath.APPROVED_WRAPPER
    assert config.policy.max_lines_by_role[Role("service")] == 400
    assert config.catalog.entries[SymbolId("httpx.Client.get")].effects == frozenset(
        {Effect.IO_BLOCKING, Effect.EXTERNAL_CALL}
    )
    assert config.catalog.entries[SymbolId("httpx.AsyncClient.get")].effects == frozenset(
        {Effect.EXTERNAL_CALL}
    )
    assert "sqlalchemy." not in config.policy.security.risky_symbol_prefixes
    assert Role("router") in config.policy.boundaries.entry_roles
    assert Role("query") in config.policy.boundaries.query_roles
    assert SymbolId("httpx.AsyncClient") in config.policy.boundaries.external_client_constructors
    assert SymbolId("httpx.AsyncClient.get") in config.policy.code.raw_test_http_calls
    assert ProjectPath("tests") in config.policy.code.test_root_paths
    assert Role("raw_query") in config.policy.boundaries.raw_query_roles
    assert Role("model") in config.policy.boundaries.schema_sql_roles
    assert "server_default" in config.policy.boundaries.schema_sql_argument_names
    assert "Adapter" in config.policy.boundaries.adapter_implementation_suffixes


def test_v4_cache_defaults_and_valid_override(tmp_path: Path) -> None:
    _write(tmp_path)
    config = load_project_configuration(tmp_path)
    assert config.cache_enabled is True
    assert config.cache_directory == ProjectPath(".taut_cache")
    (tmp_path / ".policy" / "policy.toml").write_text(
        _VALID + '\n[cache]\nenabled = false\ndirectory = "cache-data"'
    )
    config = load_project_configuration(tmp_path)
    assert config.cache_enabled is False
    assert config.cache_directory == ProjectPath("cache-data")


@pytest.mark.parametrize(
    "cache_text",
    [
        "[cache]\nunknown = true",
        "[cache]\nenabled = 'yes'",
        "[cache]\ndirectory = '../outside'",
        "[cache]\ndirectory = '/tmp/cache'",
    ],
)
def test_cache_configuration_rejects_unknown_type_and_unsafe_paths(
    tmp_path: Path, cache_text: str
) -> None:
    _write(tmp_path, _VALID + "\n" + cache_text)
    with pytest.raises((PolicyConfigError, ValueError)):
        load_project_configuration(tmp_path)


def test_missing_configuration_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(PolicyConfigError, match="missing"):
        load_project_configuration(tmp_path)


def test_strict_v4_requires_every_assurance_feature_decision(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "schema_version = 4\npacks = ['taut.backend']\n[assurance.features]\napi='absent'",
    )

    with pytest.raises(PolicyConfigError, match="missing feature decisions"):
        load_project_configuration(tmp_path)


@pytest.mark.parametrize(
    "content",
    [
        "schema_version = 1",
        "schema_version = 4\npacks = ['taut.backend']\n[rules]\nTIME001 = 'off'",
        "schema_version = 4\npacks = ['taut.backend']\n[rules]\nCAT001 = 'enforced'",
        "schema_version = 4\npacks = ['taut.backend']\n[rules]\nUNKNOWN001 = 'enforced'",
        "schema_version = 4\npacks = ['taut.backend']\nunknown = true",
        "schema_version = 4\npacks = ['taut.backend']\n[project]\nunknown = true",
        (
            "schema_version = 4\npacks = ['taut.backend']\n[[roles]]\n"
            "name='service'\npatterns=['**']\nunknown=true"
        ),
        (
            "schema_version = 4\npacks = ['taut.backend']\n[[zones]]\n"
            "name='test'\npatterns=['tests/**']\nunknown=true"
        ),
        (
            "schema_version = 4\npacks = ['taut.backend']\n[[effects]]\n"
            "symbol='app.x'\neffects=['unknown.effect']"
        ),
        "schema_version = 4\npacks = ['taut.backend']\n[architecture]\nunknown=true",
        "schema_version = 4\npacks = ['taut.backend']\n[transaction]\nunknown=true",
        "schema_version = 4\npacks = ['taut.backend']\n[[boundaries]]\nunknown=true",
        "schema_version = 4\npacks = ['taut.backend']\n[size]\nunknown=true",
        "schema_version = 4\npacks = ['taut.backend']\n[boundary_extensions]\nunknown=true",
        "schema_version = 4\npacks = ['taut.backend']\n[security]\nallowed_roles=['service']",
        "schema_version = 4\npacks = ['taut.backend']\n[code_conventions]\nunknown=[]",
    ],
)
def test_unknown_or_weakening_configuration_is_rejected(
    tmp_path: Path,
    content: str,
) -> None:
    _write(tmp_path, content)

    with pytest.raises(PolicyConfigError):
        load_project_configuration(tmp_path)


def test_architecture_map_must_cover_declared_roles(tmp_path: Path) -> None:
    _write(
        tmp_path,
        f"""
schema_version = 4\npacks = ['taut.backend']
[[roles]]
name = "service"
patterns = ["app/**"]
{assurance_toml()}
""".strip(),
    )

    with pytest.raises(PolicyConfigError, match="missing roles"):
        load_project_configuration(tmp_path)


def test_decision_configuration_digest_changes_with_manifest_and_catalog(tmp_path: Path) -> None:
    _write(tmp_path)
    first = load_project_configuration(tmp_path).digest()
    policy = tmp_path / ".policy" / "policy.toml"
    policy.write_text(_VALID.replace('patterns = ["src/app/**"]', 'patterns = ["src/core/**"]'))
    second = load_project_configuration(tmp_path).digest()

    assert first != second
    assert len(first) == 64


def test_manifest_rejects_overlapping_roles_and_zones() -> None:
    location = ConfigLocation(ProjectPath("policy.toml"))
    snapshot = analyze(make_source("app/service.py", "value = 1"))
    overlapping_roles = ProjectManifest(
        roles=(
            RoleMatcher(Role("service"), ("app/**",), location),
            RoleMatcher(Role("other"), ("app/service.py",), location),
        ),
        zones=(),
        default_zone=Zone("prod"),
        source=location,
    )
    overlapping_zones = ProjectManifest(
        roles=(),
        zones=(
            ZoneMatcher(Zone("prod"), ("app/**",), location),
            ZoneMatcher(Zone("test"), ("app/service.py",), location),
        ),
        default_zone=Zone("prod"),
        source=location,
    )

    with pytest.raises(ValueError, match="role"):
        overlapping_roles.classify(snapshot)
    with pytest.raises(ValueError, match="zone"):
        overlapping_zones.classify(snapshot)


def test_role_priority_and_exclude_make_overlaps_explicit() -> None:
    location = ConfigLocation(ProjectPath("policy.toml"))
    snapshot = analyze(
        make_source("app/dtos/report_snapshot.py", "value = 1"),
        make_source("app/dtos/report.py", "value = 1"),
    )
    manifest = ProjectManifest(
        roles=(
            RoleMatcher(Role("contract"), ("app/dtos/**",), location),
            RoleMatcher(
                Role("snapshot"),
                ("app/dtos/*_snapshot.py",),
                location,
                priority=10,
            ),
        ),
        zones=(),
        default_zone=Zone("prod"),
        source=location,
    )

    classified = manifest.classify(snapshot)

    assert classified.get(ModuleId("app.dtos.report_snapshot")).role == Role("snapshot")
    assert classified.get(ModuleId("app.dtos.report")).role == Role("contract")


def test_policy_validation_allows_arch000_to_report_unassigned_module() -> None:
    snapshot = analyze(make_source("app/service.py", "value = 1"))
    context = make_context(
        snapshot,
        roles={},
        levels={"ARCH000": RuleLevel.ENFORCED, "ARCH001": RuleLevel.ENFORCED},
    )

    validate_classification_for_policy(context.classification, context.policy)


def test_effect_resolver_distinguishes_match_no_match_and_unresolved() -> None:
    snapshot = analyze(
        make_source("app/service.py", "from datetime import datetime\ndatetime.now()\nunknown()")
    )
    calls = snapshot.modules[ModuleId("app.service")].calls
    catalog = default_project_configuration().catalog
    resolver = EffectResolver()

    assert resolver.resolve(calls[0], catalog).state is EffectResolutionState.MATCHED
    assert resolver.resolve(calls[1], catalog).state is EffectResolutionState.SYMBOL_UNRESOLVED
    assert (
        resolver.resolve(calls[0], EffectCatalog(FrozenMap())).state
        is EffectResolutionState.NO_MATCH
    )


def test_catalog_rejects_key_mismatch_and_empty_effects() -> None:
    with pytest.raises(ValueError, match="at least one"):
        CatalogEntry(SymbolId("app.clock.now"), frozenset(), AccessPath.DIRECT)
    entry = CatalogEntry(SymbolId("app.clock.now"), frozenset({Effect.TIME_NOW}), AccessPath.DIRECT)
    with pytest.raises(ValueError, match="key"):
        EffectCatalog(FrozenMap(((SymbolId("app.clock.other"), entry),)))


def test_default_configuration_is_stable() -> None:
    assert default_project_configuration().digest() == default_project_configuration().digest()


def test_builtin_boundary_defaults_can_only_be_extended(tmp_path: Path) -> None:
    _write(
        tmp_path,
        _VALID
        + """

[boundary_extensions]
entry_roles = ["webhook"]
database_modules = ["project_db"]
external_client_constructors = ["vendor_sdk.Client"]
settings_constructors = ["app.settings.Settings"]
adapter_implementation_symbols = ["app.vendor.SpecialConnection"]
adapter_implementation_suffixes = ["Connector"]
implementation_construction_roles = ["factory"]
raw_query_roles = ["repository_raw"]
raw_query_wrappers = ["app.raw_query.execute_named"]
schema_sql_roles = ["db_schema"]
schema_sql_argument_names = ["mysql_where"]
raw_sql_execution_methods = ["execute_sql"]

[code_conventions]
dto_name_suffixes = ["Payload"]
non_str_enum_exceptions = ["app.enums.NumericCode"]
test_root_paths = ["backend/tests"]
raw_test_http_calls = ["project_test.Client.get"]
test_http_fixture_roles = ["test_fixture"]
""",
    )

    policy = load_project_configuration(tmp_path).policy

    assert {Role("router"), Role("webhook")} <= policy.boundaries.entry_roles
    assert {ModuleId("sqlalchemy"), ModuleId("project_db")} <= set(
        policy.boundaries.database_modules
    )
    assert {
        SymbolId("httpx.AsyncClient"),
        SymbolId("vendor_sdk.Client"),
    } <= set(policy.boundaries.external_client_constructors)
    assert {"Data", "Result", "Row", "Payload"} == set(policy.code.dto_name_suffixes)
    assert policy.code.non_str_enum_exceptions == frozenset({SymbolId("app.enums.NumericCode")})
    assert {ProjectPath("tests"), ProjectPath("backend/tests")} == set(policy.code.test_root_paths)
    assert {
        SymbolId("httpx.AsyncClient.get"),
        SymbolId("project_test.Client.get"),
    } <= set(policy.code.raw_test_http_calls)
    assert Role("factory") in policy.boundaries.implementation_construction_roles
    assert SymbolId("app.vendor.SpecialConnection") in (
        policy.boundaries.adapter_implementation_symbols
    )
    assert {"Adapter", "Connector"} <= set(policy.boundaries.adapter_implementation_suffixes)
    assert {Role("raw_query"), Role("repository_raw")} <= policy.boundaries.raw_query_roles
    assert SymbolId("app.raw_query.execute_named") in policy.boundaries.raw_query_wrappers
    assert {Role("model"), Role("db_schema")} <= policy.boundaries.schema_sql_roles
    assert {"server_default", "mysql_where"} <= set(policy.boundaries.schema_sql_argument_names)
    assert {"execute", "execute_sql"} <= set(policy.boundaries.raw_sql_execution_methods)
    assert Role("test_fixture") in policy.code.test_http_fixture_roles
