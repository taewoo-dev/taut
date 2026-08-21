from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from tests.utils.builders import analyze, make_context, make_source

from taut.analysis.contracts import ContextManagerProvider, ResolverSettings, SourceInput
from taut.analysis.semantic_model import SnapshotSemanticModel
from taut.configuration.catalog import AccessPath, CatalogEntry, Effect
from taut.configuration.effective_policy import (
    BoundaryPolicy,
    CodeConventionPolicy,
    SecurityPolicy,
)
from taut.configuration.manifest import Role
from taut.domain.evaluations import RuleLevel, RuleTarget, RuleTargetRef, RuleVerdict
from taut.domain.facts import ResolutionState
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, RuleId, SymbolId
from taut.domain.ignores import InlineIgnore
from taut.domain.location import ProjectPath, SourceRange
from taut.finding_processing.finding_processor import FindingProcessor
from taut.policy.engine import PolicyEngine, PolicyRunResult
from taut.policy.rules import builtin_rule_registry
from taut.policy.rules.helpers import target_uncertainty

_ROOT = Path(__file__).resolve().parents[2]
_MATRIX = json.loads(
    (_ROOT / "docs/refactoring/backend-taut/uncertainty-migration-matrix.json").read_text()
)


def _boundary_policy() -> BoundaryPolicy:
    return BoundaryPolicy(
        entry_roles=frozenset({Role("router"), Role("task"), Role("consumer")}),
        service_roles=frozenset({Role("service")}),
        contract_roles=frozenset({Role("contract")}),
        adapter_roles=frozenset({Role("adapter")}),
        query_roles=frozenset({Role("query")}),
        model_roles=frozenset({Role("model")}),
        bootstrap_roles=frozenset({Role("bootstrap")}),
        configuration_roles=frozenset({Role("configuration")}),
        external_modules=(ModuleId("vendor_sdk"),),
        database_modules=(ModuleId("sqlalchemy"),),
        transport_modules=(ModuleId("fastapi"), ModuleId("starlette")),
        contract_forbidden_modules=(ModuleId("fastapi"),),
        adapter_forbidden_modules=(ModuleId("sqlalchemy"),),
        adapter_forbidden_calls=(SymbolId("sqlalchemy.select"),),
        database_statement_calls=tuple(
            SymbolId(value)
            for value in (
                "sqlalchemy.delete",
                "sqlalchemy.insert",
                "sqlalchemy.scoped_query",
                "sqlalchemy.select",
                "sqlalchemy.update",
            )
        ),
        transport_exception_calls=(SymbolId("fastapi.HTTPException"),),
        dependency_injection_calls=(SymbolId("fastapi.Depends"),),
        external_client_constructors=(SymbolId("httpx.AsyncClient"),),
        adapter_implementation_suffixes=("Adapter", "Client", "Gateway", "Harness"),
        settings_constructors=(SymbolId("app.settings.Settings"),),
        session_type_symbols=(SymbolId("sqlalchemy.ext.asyncio.AsyncSession"),),
        raw_sql_calls=(SymbolId("sqlalchemy.text"),),
        database_owner_names=("conn", "connection", "db", "session"),
        database_primitive_methods=("add", "add_all", "delete", "execute", "flush", "get", "merge"),
        query_write_method_prefixes=(
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
        http_timeout_calls=(SymbolId("httpx.AsyncClient"),),
        logged_external_calls=(SymbolId("app.clients.payment_client"), SymbolId("httpx")),
        external_call_wrappers=frozenset({SymbolId("app.observability.external_call")}),
    )


def _code_policy() -> CodeConventionPolicy:
    return CodeConventionPolicy(
        dto_roles=frozenset({Role("dto")}),
        schema_roles=frozenset({Role("schema")}),
        router_roles=frozenset({Role("router")}),
        service_roles=frozenset({Role("service")}),
        model_roles=frozenset({Role("model")}),
        snapshot_roles=frozenset({Role("snapshot")}),
        request_config_symbols=frozenset({SymbolId("app.config.REQUEST_CONFIG")}),
        response_config_symbols=frozenset({SymbolId("app.config.RESPONSE_CONFIG")}),
        shared_enum_modules=(ModuleId("app.fixture"),),
        forbidden_runtime_calls=("*.delay", "httpx.AsyncClient.get"),
        exception_base_symbols=frozenset({SymbolId("app.errors.AppException")}),
        abstract_exception_symbols=frozenset({SymbolId("app.errors.AppException")}),
        error_code_enum_symbols=frozenset({SymbolId("app.errors.ErrorCode")}),
        test_root_paths=(ProjectPath("tests"),),
        raw_test_http_calls=(SymbolId("httpx.AsyncClient.get"),),
        raw_test_http_client_constructors=(SymbolId("httpx.AsyncClient"),),
    )


def _security_policy() -> SecurityPolicy:
    return SecurityPolicy(
        allowed_roles=FrozenMap(
            (
                (Effect.SECURITY_ENVIRONMENT, frozenset({Role("configuration")})),
                (Effect.SECURITY_SECRET, frozenset({Role("adapter")})),
                (Effect.SECURITY_TOKEN, frozenset({Role("security")})),
            )
        ),
        risky_symbol_prefixes=("requests.",),
    )


def _fixture_sources(paths: tuple[str, ...]) -> tuple[SourceInput, ...]:
    files: list[Path] = []
    for relative in paths:
        path = _ROOT / relative
        files.extend(sorted(path.rglob("*.py")) if path.is_dir() else (path,))
    values: list[SourceInput] = []
    for path in files:
        name = path.stem if len(files) > 1 else "fixture"
        values.append(make_source(f"app/{name}.py", path.read_text(), module_id=f"app.{name}"))
    return tuple(values)


def _roles(rule_id: str, variant: str) -> dict[str, tuple[str, ...]]:
    role = {
        "BOUNDARY001": "task",
        "BOUNDARY002": "service",
        "BOUNDARY003": "contract",
        "ADAPTER001": "adapter",
        "ENTRY001": "router",
        "SERVICE001": "service",
        "QUERY001": "query",
        "MODEL001": "model",
        "WIRING001": "bootstrap" if variant == "compliant" else "service",
        "ADAPTER002": "adapter",
        "DEPENDS001": "router" if variant == "compliant" else "service",
        "CONFIG001": "configuration" if variant == "compliant" else "service",
        "TEST001": "test",
        "TEST002": "test",
        "HTTP001": "adapter",
        "LOG001": "adapter",
        "DTO001": "dto",
        "DTO002": "dto",
        "SNAPSHOT001": "snapshot",
        "SCHEMA001": "schema",
        "SCHEMA002": "schema",
        "SCHEMA003": "schema" if variant == "compliant" else "router",
        "API001": "router",
        "API002": "schema",
        "API003": "router",
        "ENUM001": "enum",
        "ORM001": "model",
        "ORM002": "model",
        "DB001": "model",
        "SQL001": "model",
        "SEC001": "configuration" if variant == "compliant" else "service",
        "CAT001": "adapter",
        "TX001": "service" if variant == "compliant" else "task",
        "SESSION001": "service" if variant == "compliant" else "task",
        "SESSION002": "service",
        "SESSION003": "service",
    }.get(rule_id, "service")
    if rule_id == "ARCH000" and variant == "violation":
        return {}
    return {role: ("app/**",)}


def _run_regular_fixture(
    rule_id: str,
    variant: str,
    provider_state: ResolutionState | None = None,
    missing_capability: str | None = None,
    incomplete: bool = False,
    fact_state: ResolutionState | None = None,
    inject_relevant: bool = True,
) -> PolicyRunResult:
    definition = builtin_rule_registry().definitions[RuleId(rule_id)]
    paths = (
        definition.compliant_fixtures if variant == "compliant" else definition.violation_fixtures
    )
    sources = _fixture_sources(paths)
    if rule_id == "TEST001":
        test_path = "tests/conftest.py" if variant == "compliant" else "tests/unit/conftest.py"
        sources = (make_source(test_path, sources[0].content),)
    elif rule_id == "TEST002":
        sources = (make_source("tests/test_api.py", sources[0].content),)
    extras: list[SourceInput] = []
    roles = _roles(rule_id, variant)
    allowed: dict[str, frozenset[str]] = {role: frozenset(roles) for role in roles}
    if rule_id == "ARCH001":
        fixture_text = sources[0].content
        if variant == "compliant":
            sources = (make_source("app/router.py", fixture_text),)
            extras.append(make_source("app/service.py", "value = 1"))
            roles = {"router": ("app/router.py",), "service": ("app/service.py",)}
            allowed = {"router": frozenset({"service"}), "service": frozenset({"service"})}
        else:
            sources = (make_source("app/domain.py", fixture_text),)
            extras.append(make_source("app/router.py", "route = 1"))
            roles = {"domain": ("app/domain.py",), "router": ("app/router.py",)}
            allowed = {"domain": frozenset({"domain"}), "router": frozenset({"router"})}
    sources = (*sources, *extras)
    resolver = ResolverSettings(
        context_manager_providers=(
            ContextManagerProvider(
                SymbolId("app.database.get_async_session"),
                SymbolId("sqlalchemy.ext.asyncio.AsyncSession"),
            ),
        )
        if rule_id == "TX002"
        else ()
    )
    snapshot = analyze(*sources, resolver=resolver)
    time_wrapper = CatalogEntry(
        SymbolId("app.clock.utc_now"),
        frozenset({Effect.TIME_NOW}),
        AccessPath.APPROVED_WRAPPER,
    )
    context = make_context(
        snapshot,
        roles=roles,
        zones={"test": ("tests/**",)} if rule_id in {"TEST001", "TEST002"} else None,
        levels={rule_id: RuleLevel.ADVISORY if rule_id == "CAT001" else RuleLevel.ENFORCED},
        allowed_imports=allowed,
        transaction_owners=frozenset({"service"}),
        transaction_session_providers=frozenset({"app.database.get_async_session"}),
        import_boundaries=(("task-db", frozenset({"task"}), ("app.models", "sqlalchemy")),),
        default_max_lines=500,
        max_lines_by_role={"service": 1} if rule_id == "SIZE001" else None,
        boundary_policy=_boundary_policy(),
        code_policy=_code_policy(),
        security_policy=_security_policy(),
        extra_catalog_entries=(time_wrapper,),
        provider_state=provider_state,
        missing_capability=missing_capability,
        incomplete_modules=frozenset(module.value for module in snapshot.modules)
        if incomplete
        else frozenset(),
        fact_state=fact_state,
        fact_candidates=(
            tuple(
                SymbolId(value)
                for value in (
                    GROUP_B_RELEVANT_SYMBOLS | GROUP_C_RELEVANT_SYMBOLS | GROUP_D_RELEVANT_SYMBOLS
                ).get(rule_id, ())
            )
            if inject_relevant
            else ()
        ),
    )
    return PolicyEngine(builtin_rule_registry()).run(context)


def _assert_ignore_fixture(variant: str) -> None:
    path = ProjectPath("app/fixture.py")
    ignores: tuple[InlineIgnore, ...] = ()
    if variant == "violation":
        ignores = (InlineIgnore(path, 0, RuleId("TIME001"), SourceRange(path, 0, 11, 0, 42)),)
    policy = make_context(
        analyze(make_source(path.value, "value = 1")),
        roles={"service": ("app/**",)},
        levels={"IGNORE001": RuleLevel.ENFORCED},
    ).policy
    result = FindingProcessor().process(
        findings=(), policy=policy, help_by_rule=FrozenMap(), ignores=ignores
    )
    has_violation = any(item.rule_id == RuleId("IGNORE001") for item in result.diagnostics)
    assert has_violation is (variant == "violation")


@pytest.mark.contract
@pytest.mark.parametrize("variant", ["compliant", "violation"])
@pytest.mark.parametrize(
    "rule_id",
    [rule_id.value for rule_id in builtin_rule_registry().definitions],
)
def test_registered_rule_fixtures_have_expected_semantics(rule_id: str, variant: str) -> None:
    if rule_id == "IGNORE001":
        _assert_ignore_fixture(variant)
        return
    result = _run_regular_fixture(rule_id, variant)
    findings = tuple(item for item in result.findings if item.rule_id == RuleId(rule_id))
    indeterminate = tuple(
        item
        for item in result.evaluations
        if item.rule_id == RuleId(rule_id) and item.verdict.value == "indeterminate"
    )

    assert not indeterminate, f"{rule_id} {variant} was indeterminate"
    assert bool(findings) is (variant == "violation")


GROUP_A_RULES = (
    "API001",
    "API002",
    "API003",
    "DTO001",
    "DTO002",
    "SNAPSHOT001",
    "SCHEMA001",
    "SCHEMA002",
    "SCHEMA003",
    "ENUM001",
    "IGNORE001",
)
GROUP_B_RULES = (
    "ADAPTER001",
    "ARCH001",
    "ARCH002",
    "BOUNDARY001",
    "BOUNDARY002",
    "BOUNDARY003",
    "DEPENDS001",
    "ENTRY001",
    "MODEL001",
    "QUERY001",
    "SERVICE001",
)
GROUP_B_RELEVANT_SYMBOLS = {
    "DEPENDS001": ("fastapi.Depends",),
    "ENTRY001": ("httpx.AsyncClient",),
    "SERVICE001": ("sqlalchemy.select",),
    "QUERY001": ("sqlalchemy.select",),
    "MODEL001": ("httpx.AsyncClient",),
}
GROUP_C_RULES = (
    "ADAPTER002",
    "ARCH000",
    "CONFIG001",
    "EXC001",
    "HTTP001",
    "IMPORT001",
    "LOG001",
    "SEC001",
    "SIZE001",
    "TEST001",
    "TEST002",
    "WIRING001",
)
GROUP_C_SEMANTIC_RULES = set(GROUP_C_RULES) - {"IMPORT001", "SIZE001", "TEST001"}
GROUP_C_RELEVANT_SYMBOLS = {
    "CONFIG001": ("app.settings.Settings",),
    "HTTP001": ("httpx.AsyncClient",),
    "LOG001": ("httpx",),
    "SEC001": ("os.getenv",),
    "TEST002": ("httpx.AsyncClient",),
    "WIRING001": ("httpx.AsyncClient",),
    "EXC001": (
        "app.errors.AppException.__init__",
        "app.fixture.UserNotFoundError.__init__",
    ),
}
GROUP_D_RULES = (
    "CAT001",
    "DB001",
    "IMPORT002",
    "ORM001",
    "ORM002",
    "RUNTIME001",
    "SESSION001",
    "SESSION002",
    "SESSION003",
    "SQL001",
    "TIME001",
    "TX001",
    "TX002",
    "ASYNC001",
)
GROUP_D_RELEVANT_SYMBOLS = {
    "CAT001": ("requests.custom_call",),
    "DB001": ("sqlalchemy.DateTime",),
    "IMPORT002": ("builtins.__import__",),
    "ORM001": ("sqlalchemy.orm.relationship",),
    "ORM002": ("sqlalchemy.Enum",),
    "RUNTIME001": ("httpx.AsyncClient.get",),
    "SESSION001": ("app.database.get_async_session",),
    "SESSION002": ("app.database.get_async_session",),
    "SESSION003": ("sqlalchemy.ext.asyncio.AsyncSession",),
    "SQL001": ("sqlalchemy.Connection.execute",),
    "TIME001": ("datetime.datetime.now",),
    "TX001": ("sqlalchemy.ext.asyncio.AsyncSession.commit",),
    "TX002": ("app.clients.payment_client",),
    "ASYNC001": ("time.sleep",),
}
_VERDICT_BY_MATRIX = {
    "evaluate": RuleVerdict.PASS,
    "indeterminate": RuleVerdict.INDETERMINATE,
    "not_applicable": RuleVerdict.NOT_APPLICABLE,
}
GROUP_D_MATRIX_EXPECTED = {
    row["id"]: {
        state: _VERDICT_BY_MATRIX[verdict] for state, verdict in row["resolution_policy"].items()
    }
    for row in _MATRIX["rules"]
    if row["id"] in GROUP_D_RULES
}
GROUP_C_UNRELATED_EXPECTED = {
    rule: (RuleVerdict.NOT_APPLICABLE if rule in {"HTTP001", "LOG001"} else RuleVerdict.PASS)
    for rule in GROUP_C_RELEVANT_SYMBOLS
}
GROUP_C_MATRIX_EXPECTED = {
    item["id"]: {
        state: {
            "evaluate": RuleVerdict.PASS,
            "indeterminate": RuleVerdict.INDETERMINATE,
            "not_applicable": RuleVerdict.NOT_APPLICABLE,
        }[verdict]
        for state, verdict in item["resolution_policy"].items()
    }
    for item in _MATRIX["rules"]
    if item["id"] in GROUP_C_SEMANTIC_RULES
}
EXPECTED_GROUP_C_RESOLVED = {rule: "pass" for rule in GROUP_C_RULES}
GROUP_B_EXPECTED = {
    rule: {
        state: (
            "indeterminate"
            if rule in GROUP_B_RELEVANT_SYMBOLS
            and state in {ResolutionState.CONDITIONAL, ResolutionState.AMBIGUOUS}
            else "not_applicable"
            if rule == "DEPENDS001"
            and state in {ResolutionState.UNRESOLVED, ResolutionState.DYNAMIC}
            else "pass"
        )
        for state in ResolutionState
    }
    for rule in GROUP_B_RULES
}
PROVIDER_BACKED_GROUP_A_RULES = {
    "API001",
    "API002",
    "API003",
    "DTO001",
    "DTO002",
    "SCHEMA001",
    "SCHEMA002",
    "SCHEMA003",
}
STATE_SENSITIVE_GROUP_A_RULES = {"API001", "API002", "API003", "SCHEMA001", "SCHEMA002"}
PROVIDER_REQUIRED_CAPABILITIES = (
    ("API001", "taut.fastapi.endpoints@1"),
    ("API002", "taut.pydantic.fields@1"),
    ("API003", "taut.fastapi.routers@1"),
    ("DTO001", "taut.pydantic.models@1"),
    ("DTO002", "taut.pydantic.models@1"),
    ("SCHEMA001", "taut.pydantic.configs@1"),
    ("SCHEMA002", "taut.pydantic.models@1"),
    ("SCHEMA003", "taut.pydantic.operations@1"),
)
EXPECTED_GROUP_A_RESOLVED = {
    "API001": "pass",
    "API002": "pass",
    "API003": "pass",
    "DTO001": "pass",
    "DTO002": "pass",
    "SNAPSHOT001": "pass",
    "SCHEMA001": "pass",
    "SCHEMA002": "pass",
    "SCHEMA003": "pass",
    "ENUM001": "pass",
    "IGNORE001": "not_applicable",
}


@pytest.mark.contract
@pytest.mark.parametrize("rule_id", GROUP_A_RULES)
@pytest.mark.parametrize("state", tuple(ResolutionState))
def test_group_a_evaluators_execute_real_fixtures_for_provider_states(
    rule_id: str, state: ResolutionState
) -> None:
    result = _run_regular_fixture(rule_id, "compliant", provider_state=state)
    evaluations = tuple(item for item in result.evaluations if item.rule_id == RuleId(rule_id))
    assert evaluations, rule_id
    assert not result.engine_issues
    expected = EXPECTED_GROUP_A_RESOLVED[rule_id]
    if state is not ResolutionState.RESOLVED and rule_id in STATE_SENSITIVE_GROUP_A_RULES:
        expected = "indeterminate"
    assert {item.verdict.value for item in evaluations} == {expected}
    if expected == "indeterminate":
        assert all(item.verdict.value == "indeterminate" for item in evaluations)
        assert all(item.reason is not None for item in evaluations)
        assert {item.reason.code for item in evaluations if item.reason is not None} == {
            "uncertain_provider_fact"
        }


@pytest.mark.contract
@pytest.mark.parametrize("rule_id", GROUP_B_RULES)
def test_group_b_evaluators_propagate_incomplete_module_facts(rule_id: str) -> None:
    result = _run_regular_fixture(rule_id, "compliant", incomplete=True)
    evaluations = tuple(item for item in result.evaluations if item.rule_id == RuleId(rule_id))
    assert evaluations
    assert {item.verdict for item in evaluations} == {RuleVerdict.INDETERMINATE}
    assert {item.reason.code for item in evaluations if item.reason is not None} == {
        "incomplete_module"
    }


@pytest.mark.contract
@pytest.mark.parametrize("rule_id", GROUP_B_RULES)
@pytest.mark.parametrize("state", tuple(ResolutionState))
def test_group_b_evaluators_execute_call_resolution_states(
    rule_id: str, state: ResolutionState
) -> None:
    result = _run_regular_fixture(rule_id, "compliant", fact_state=state)
    evaluations = tuple(item for item in result.evaluations if item.rule_id == RuleId(rule_id))
    assert evaluations
    expected = GROUP_B_EXPECTED[rule_id][state]
    assert {item.verdict.value for item in evaluations} == {expected}
    if expected == "indeterminate":
        assert {item.reason.code for item in evaluations if item.reason is not None} == {
            "uncertain_symbol"
        }


@pytest.mark.contract
@pytest.mark.parametrize("rule_id", GROUP_B_RULES)
def test_group_b_unrelated_uncertainty_does_not_propagate(rule_id: str) -> None:
    result = _run_regular_fixture(
        rule_id,
        "compliant",
        fact_state=ResolutionState.CONDITIONAL,
        inject_relevant=False,
    )
    evaluations = tuple(item for item in result.evaluations if item.rule_id == RuleId(rule_id))
    assert evaluations
    expected = "not_applicable" if rule_id == "DEPENDS001" else "pass"
    assert {item.verdict.value for item in evaluations} == {expected}


@pytest.mark.contract
@pytest.mark.parametrize("rule_id", GROUP_C_RULES)
def test_group_c_resolved_fixtures_execute_evaluators(rule_id: str) -> None:
    result = _run_regular_fixture(rule_id, "compliant")
    evaluations = tuple(item for item in result.evaluations if item.rule_id == RuleId(rule_id))
    assert evaluations
    assert not result.engine_issues
    assert {item.verdict.value for item in evaluations} == {EXPECTED_GROUP_C_RESOLVED[rule_id]}


@pytest.mark.contract
@pytest.mark.parametrize("rule_id", GROUP_C_RULES)
def test_group_c_incomplete_facts_are_indeterminate(rule_id: str) -> None:
    result = _run_regular_fixture(rule_id, "compliant", incomplete=True)
    evaluations = tuple(item for item in result.evaluations if item.rule_id == RuleId(rule_id))
    assert evaluations
    assert {item.verdict for item in evaluations} == {RuleVerdict.INDETERMINATE}
    assert all(item.reason is not None for item in evaluations)


@pytest.mark.contract
@pytest.mark.parametrize("rule_id", tuple(GROUP_C_RELEVANT_SYMBOLS))
@pytest.mark.parametrize("state", (ResolutionState.CONDITIONAL, ResolutionState.AMBIGUOUS))
def test_group_c_relevant_candidates_are_indeterminate(
    rule_id: str, state: ResolutionState
) -> None:
    result = _run_regular_fixture(
        rule_id,
        "compliant",
        fact_state=state,
    )
    evaluations = tuple(item for item in result.evaluations if item.rule_id == RuleId(rule_id))
    assert evaluations
    assert {item.verdict for item in evaluations} == {RuleVerdict.INDETERMINATE}
    assert {item.reason.code for item in evaluations if item.reason is not None} == {
        "uncertain_symbol"
    }


@pytest.mark.contract
@pytest.mark.parametrize("rule_id", tuple(GROUP_C_RELEVANT_SYMBOLS))
def test_group_c_unrelated_unresolved_facts_keep_compatible_verdict(rule_id: str) -> None:
    result = _run_regular_fixture(
        rule_id,
        "compliant",
        fact_state=ResolutionState.CONDITIONAL,
        inject_relevant=False,
    )
    evaluations = tuple(item for item in result.evaluations if item.rule_id == RuleId(rule_id))
    assert evaluations
    assert {item.verdict for item in evaluations} == {GROUP_C_UNRELATED_EXPECTED[rule_id]}


@pytest.mark.contract
@pytest.mark.parametrize("rule_id", GROUP_C_RULES)
@pytest.mark.parametrize("state", tuple(ResolutionState))
def test_group_c_all_resolution_states_execute_evaluators(
    rule_id: str, state: ResolutionState
) -> None:
    result = _run_regular_fixture(rule_id, "compliant", fact_state=state)
    evaluations = tuple(item for item in result.evaluations if item.rule_id == RuleId(rule_id))
    assert evaluations
    assert not result.engine_issues
    expected = GROUP_C_MATRIX_EXPECTED.get(rule_id, {}).get(state.value, RuleVerdict.PASS)
    if rule_id not in GROUP_C_SEMANTIC_RULES:
        expected = RuleVerdict.PASS
    assert {item.verdict for item in evaluations} == {expected}


@pytest.mark.contract
@pytest.mark.parametrize("rule_id", GROUP_D_RULES)
@pytest.mark.parametrize("state", tuple(ResolutionState))
def test_group_d_matrix_exact_state_contract(rule_id: str, state: ResolutionState) -> None:
    result = _run_regular_fixture(
        rule_id,
        "compliant",
        fact_state=state,
        inject_relevant=(
            GROUP_D_MATRIX_EXPECTED[rule_id][state.value] is RuleVerdict.INDETERMINATE
        ),
    )
    evaluations = tuple(item for item in result.evaluations if item.rule_id == RuleId(rule_id))
    assert evaluations
    expected = GROUP_D_MATRIX_EXPECTED[rule_id][state.value]
    assert {item.verdict for item in evaluations} == {expected}
    if expected is RuleVerdict.INDETERMINATE:
        reason = (
            "uncertain_effect"
            if rule_id in {"TIME001", "TX001", "ASYNC001"}
            else "uncertain_symbol"
        )
        assert {item.reason.code for item in evaluations if item.reason is not None} == {reason}


@pytest.mark.contract
@pytest.mark.parametrize("rule_id", GROUP_D_RULES)
def test_group_d_unrelated_candidates_do_not_propagate(rule_id: str) -> None:
    result = _run_regular_fixture(
        rule_id, "compliant", fact_state=ResolutionState.CONDITIONAL, inject_relevant=False
    )
    evaluations = tuple(item for item in result.evaluations if item.rule_id == RuleId(rule_id))
    assert evaluations
    expected = (
        RuleVerdict.NOT_APPLICABLE
        if GROUP_D_MATRIX_EXPECTED[rule_id]["unresolved"] is RuleVerdict.NOT_APPLICABLE
        else RuleVerdict.PASS
    )
    assert {item.verdict for item in evaluations} == {expected}


@pytest.mark.contract
@pytest.mark.parametrize("rule_id", GROUP_D_RULES)
def test_group_d_incomplete_module_facts_are_indeterminate(rule_id: str) -> None:
    result = _run_regular_fixture(rule_id, "compliant", incomplete=True)
    evaluations = tuple(item for item in result.evaluations if item.rule_id == RuleId(rule_id))
    assert evaluations
    assert {item.verdict for item in evaluations} == {RuleVerdict.INDETERMINATE}
    assert {item.reason.code for item in evaluations if item.reason is not None} <= {
        "incomplete_module",
        "incomplete_project",
        "insufficient_analysis",
    }


@pytest.mark.contract
def test_sql001_missing_sqlalchemy_provider_is_indeterminate() -> None:
    result = _run_regular_fixture(
        "SQL001", "violation", missing_capability="taut.sqlalchemy.raw_sql@1"
    )
    evaluations = tuple(item for item in result.evaluations if item.rule_id == RuleId("SQL001"))
    assert evaluations
    assert {item.verdict for item in evaluations} == {RuleVerdict.INDETERMINATE}
    assert {item.reason.code for item in evaluations if item.reason is not None} == {
        "missing_capability"
    }


@pytest.mark.contract
@pytest.mark.parametrize(("rule_id", "capability"), PROVIDER_REQUIRED_CAPABILITIES)
def test_provider_required_evaluator_wiring_reports_missing_capability(
    rule_id: str, capability: str
) -> None:
    result = _run_regular_fixture(rule_id, "compliant", missing_capability=capability)
    evaluations = tuple(item for item in result.evaluations if item.rule_id == RuleId(rule_id))
    assert evaluations
    assert {item.verdict.value for item in evaluations} == {"indeterminate"}
    assert {item.reason.code for item in evaluations if item.reason is not None} == {
        "missing_capability"
    }


@pytest.mark.contract
def test_provider_backed_group_a_ids_match_capability_contracts() -> None:
    assert {
        rule_id for rule_id, _ in PROVIDER_REQUIRED_CAPABILITIES
    } == PROVIDER_BACKED_GROUP_A_RULES


@pytest.mark.contract
def test_missing_required_provider_capability_is_indeterminate() -> None:
    snapshot = analyze(make_source("app/fixture.py", "value = 1"))
    context = make_context(snapshot, roles={"router": ("app/**",)})
    target = RuleTargetRef(RuleTarget.MODULE, module_id=ModuleId("app.fixture"))
    model_without_provider = SnapshotSemanticModel(snapshot)
    context = replace(context, model=model_without_provider)
    result = target_uncertainty(
        RuleId("API001"),
        target,
        context,
        ("taut.fastapi.endpoints@1",),
        True,
    )
    assert result is not None
    assert result.verdict is RuleVerdict.INDETERMINATE
    assert result.reason is not None
    assert result.reason.code == "missing_capability"
