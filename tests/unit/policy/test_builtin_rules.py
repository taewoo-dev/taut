from __future__ import annotations

from dataclasses import replace

from tests.utils.builders import analyze, make_context, make_source

from taut.analysis.contracts import SourceInput
from taut.configuration.catalog import AccessPath, CatalogEntry, Effect
from taut.configuration.effective_policy import (
    BoundaryPolicy,
    CodeConventionPolicy,
    PolicyApproval,
    SecurityPolicy,
)
from taut.configuration.manifest import Role
from taut.domain.evaluations import RuleVerdict
from taut.domain.facts import ResolutionState
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, RuleId, SymbolId
from taut.policy.engine import PolicyEngine, PolicyRunResult
from taut.policy.rules import builtin_rule_registry


def _run(
    *sources: SourceInput,
    roles: dict[str, tuple[str, ...]],
    allowed_imports: dict[str, frozenset[str]] | None = None,
    owners: frozenset[str] = frozenset(),
    participants: frozenset[str] = frozenset(),
    session_providers: frozenset[str] = frozenset(),
    boundary_contexts: frozenset[str] = frozenset(),
    zones: dict[str, tuple[str, ...]] | None = None,
    rule_zones: dict[str, frozenset[str]] | None = None,
    approvals: tuple[PolicyApproval, ...] = (),
    import_boundaries: tuple[
        tuple[str, frozenset[str], tuple[str, ...]]
        | tuple[str, frozenset[str], tuple[str, ...], tuple[str, ...]],
        ...,
    ] = (),
    default_max_lines: int = 700,
    max_lines_by_role: dict[str, int] | None = None,
    boundary_policy: BoundaryPolicy | None = None,
    code_policy: CodeConventionPolicy | None = None,
    security_policy: SecurityPolicy | None = None,
    entries: tuple[CatalogEntry, ...] = (),
) -> PolicyRunResult:
    snapshot = analyze(*sources)
    context = make_context(
        snapshot,
        roles=roles,
        zones=zones,
        allowed_imports=allowed_imports,
        transaction_owners=owners,
        transaction_participants=participants,
        transaction_session_providers=session_providers,
        transaction_boundary_contexts=boundary_contexts,
        rule_zones=rule_zones,
        approvals=approvals,
        import_boundaries=import_boundaries,
        default_max_lines=default_max_lines,
        max_lines_by_role=max_lines_by_role,
        boundary_policy=boundary_policy,
        code_policy=code_policy,
        security_policy=security_policy,
        extra_catalog_entries=entries,
    )
    return PolicyEngine(builtin_rule_registry()).run(context)


def _boundary_policy() -> BoundaryPolicy:
    return BoundaryPolicy(
        service_roles=frozenset({Role("service")}),
        contract_roles=frozenset({Role("contract")}),
        adapter_roles=frozenset({Role("adapter")}),
        external_modules=(ModuleId("vendor_sdk"),),
        contract_forbidden_modules=(ModuleId("fastapi"), ModuleId("vendor_sdk")),
        adapter_forbidden_modules=(ModuleId("sqlalchemy"),),
        adapter_forbidden_calls=(SymbolId("sqlalchemy.ext.asyncio.AsyncSession.execute"),),
        http_timeout_calls=(SymbolId("httpx.AsyncClient"),),
        logged_external_calls=(SymbolId("httpx"),),
        external_call_wrappers=frozenset({SymbolId("app.logging.external_call")}),
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
        shared_enum_modules=(ModuleId("app.core.enums"),),
        forbidden_runtime_calls=("*.delay",),
        exception_base_symbols=frozenset({SymbolId("app.errors.AppException")}),
        abstract_exception_symbols=frozenset({SymbolId("app.errors.AppException")}),
        error_code_enum_symbols=frozenset({SymbolId("app.codes.ErrorCode")}),
    )


def _strict_boundary_policy() -> BoundaryPolicy:
    return replace(
        _boundary_policy(),
        entry_roles=frozenset({Role("router"), Role("consumer"), Role("task")}),
        query_roles=frozenset({Role("query")}),
        model_roles=frozenset({Role("model")}),
        bootstrap_roles=frozenset({Role("bootstrap")}),
        configuration_roles=frozenset({Role("configuration")}),
        database_modules=(ModuleId("sqlalchemy"),),
        transport_modules=(ModuleId("fastapi"), ModuleId("starlette")),
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
        database_primitive_methods=(
            "add",
            "add_all",
            "delete",
            "execute",
            "flush",
            "get",
            "merge",
        ),
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
    )


def test_time_rule_fails_direct_access_and_passes_wrapper() -> None:
    direct = make_source(
        "app/service.py",
        "from datetime import datetime\nvalue = datetime.now()",
    )
    wrapped = make_source(
        "app/other.py",
        "from app.clock import utc_now\nvalue = utc_now()",
    )
    wrapper = CatalogEntry(
        SymbolId("app.clock.utc_now"),
        frozenset({Effect("time.now")}),
        AccessPath.APPROVED_WRAPPER,
    )

    result = _run(
        direct,
        wrapped,
        roles={"service": ("app/**",)},
        allowed_imports={"service": frozenset({"service"})},
        entries=(wrapper,),
    )
    time_results = tuple(item for item in result.evaluations if item.rule_id == RuleId("TIME001"))

    assert any(item.verdict is RuleVerdict.FAIL for item in time_results)
    assert any(item.verdict is RuleVerdict.PASS for item in time_results)
    assert result.findings[0].message_key == "time.direct_access"


def test_transaction_rule_uses_annotated_session_type_and_role() -> None:
    service = make_source(
        "app/service.py",
        """
from sqlalchemy.ext.asyncio import AsyncSession
async def save(session: AsyncSession):
    await session.commit()
""".strip(),
    )
    query = make_source(
        "app/query.py",
        """
from sqlalchemy.ext.asyncio import AsyncSession
async def read(session: AsyncSession):
    await session.rollback()
""".strip(),
    )

    result = _run(
        service,
        query,
        roles={"service": ("app/service.py",), "query": ("app/query.py",)},
        allowed_imports={
            "service": frozenset({"service", "query"}),
            "query": frozenset({"query"}),
        },
        owners=frozenset({"service"}),
    )
    tx_results = tuple(item for item in result.evaluations if item.rule_id == RuleId("TX001"))

    assert any(item.verdict is RuleVerdict.PASS for item in tx_results)
    assert any(item.verdict is RuleVerdict.FAIL for item in tx_results)


def test_session_rule_allows_service_and_rejects_task() -> None:
    service = make_source(
        "app/service.py",
        "from app.database import get_async_session\nget_async_session()",
    )
    task = make_source(
        "app/task.py",
        "from app.database import get_async_session\nget_async_session()",
    )

    result = _run(
        service,
        task,
        roles={"service": ("app/service.py",), "task": ("app/task.py",)},
        allowed_imports={
            "service": frozenset({"service"}),
            "task": frozenset({"task"}),
        },
        owners=frozenset({"service"}),
        session_providers=frozenset({"app.database.get_async_session"}),
    )
    session_results = tuple(
        item for item in result.evaluations if item.rule_id == RuleId("SESSION001")
    )

    assert any(item.verdict is RuleVerdict.PASS for item in session_results)
    assert any(item.verdict is RuleVerdict.FAIL for item in session_results)


def test_session_provider_may_call_another_registered_provider() -> None:
    database = make_source(
        "app/database.py",
        """
def session_factory(): ...
def get_async_session():
    return session_factory()
""".strip(),
    )

    result = _run(
        database,
        roles={"database": ("app/database.py",)},
        allowed_imports={"database": frozenset({"database"})},
        owners=frozenset({"service"}),
        session_providers=frozenset(
            {"app.database.get_async_session", "app.database.session_factory"}
        ),
    )
    session_result = next(
        item
        for item in result.evaluations
        if item.rule_id == RuleId("SESSION001") and item.verdict is RuleVerdict.PASS
    )

    assert session_result.verdict is RuleVerdict.PASS


def test_session_call_uncertainty_does_not_fan_out_to_unrelated_calls() -> None:
    module_id = ModuleId("app.service")
    snapshot = analyze(
        make_source(
            "app/service.py",
            "unrelated_one()\nunrelated_two()\nunrelated_three()\nmaybe_session()",
        )
    )
    module = snapshot.modules[module_id]
    *unrelated_calls, maybe_session = module.calls
    provider = SymbolId("app.database.get_async_session")
    unrelated_calls = [
        replace(
            call,
            ref=replace(
                call.ref,
                state=ResolutionState.AMBIGUOUS,
                symbol=None,
                candidates=(SymbolId("app.other.call"), SymbolId("app.other.alternative")),
            ),
        )
        for call in unrelated_calls
    ]
    maybe_session = replace(
        maybe_session,
        ref=replace(
            maybe_session.ref,
            state=ResolutionState.AMBIGUOUS,
            symbol=None,
            candidates=(provider, SymbolId("app.other.alternative")),
        ),
    )
    snapshot = replace(
        snapshot,
        modules=FrozenMap(((module_id, replace(module, calls=(*unrelated_calls, maybe_session))),)),
    )
    context = make_context(
        snapshot,
        roles={"service": ("app/service.py",)},
        allowed_imports={"service": frozenset({"service"})},
        transaction_owners=frozenset({"service"}),
        transaction_session_providers=frozenset({provider.value}),
    )

    result = PolicyEngine(builtin_rule_registry()).run(context)

    for rule_id in (RuleId("SESSION001"), RuleId("SESSION002")):
        evaluations = {
            evaluation.target.fact_id: evaluation
            for evaluation in result.evaluations
            if evaluation.rule_id == rule_id
        }
        assert all(
            evaluations[call.id].verdict is RuleVerdict.NOT_APPLICABLE for call in unrelated_calls
        )
        assert evaluations[maybe_session.id].verdict is RuleVerdict.INDETERMINATE


def test_boundary_rule_rejects_forbidden_imports_only_for_selected_role() -> None:
    task = make_source(
        "app/task.py",
        "from app.models.user import User\nfrom sqlalchemy import select",
    )
    service = make_source(
        "app/service.py",
        "from app.models.user import User\nfrom sqlalchemy import select",
    )

    result = _run(
        task,
        service,
        roles={"task": ("app/task.py",), "service": ("app/service.py",)},
        allowed_imports={
            "task": frozenset({"task"}),
            "service": frozenset({"service"}),
        },
        import_boundaries=(
            (
                "task-db",
                frozenset({"task"}),
                ("app.models", "app.queries", "sqlalchemy"),
            ),
        ),
    )
    boundary_results = tuple(
        item for item in result.evaluations if item.rule_id == RuleId("BOUNDARY001")
    )

    task_result = next(
        item for item in boundary_results if item.target.module_id == ModuleId("app.task")
    )
    service_result = next(
        item for item in boundary_results if item.target.module_id == ModuleId("app.service")
    )
    assert task_result.verdict is RuleVerdict.FAIL
    assert len(task_result.findings) == 2
    assert service_result.verdict is RuleVerdict.NOT_APPLICABLE


def test_boundary_rule_reports_one_finding_for_one_import_statement() -> None:
    task = make_source(
        "app/task.py",
        "from app.models.job import Job, JobStatus",
    )

    result = _run(
        task,
        roles={"task": ("app/task.py",)},
        allowed_imports={"task": frozenset({"task"})},
        import_boundaries=(("task-db", frozenset({"task"}), ("app.models",)),),
    )
    boundary_result = next(
        item for item in result.evaluations if item.rule_id == RuleId("BOUNDARY001")
    )

    assert boundary_result.verdict is RuleVerdict.FAIL
    assert len(boundary_result.findings) == 1


def test_boundary_rule_rejects_configured_resolved_call_patterns() -> None:
    service = make_source(
        "app/service.py",
        "from sqlalchemy.ext.asyncio import AsyncSession\n"
        "async def run(session: AsyncSession):\n    await session.execute('select 1')",
    )

    result = _run(
        service,
        roles={"service": ("app/service.py",)},
        allowed_imports={"service": frozenset({"service"})},
        import_boundaries=(
            (
                "service-db",
                frozenset({"service"}),
                (),
                ("sqlalchemy.ext.asyncio.AsyncSession.execute",),
            ),
        ),
    )
    boundary_result = next(
        item for item in result.evaluations if item.rule_id == RuleId("BOUNDARY001")
    )

    assert boundary_result.verdict is RuleVerdict.FAIL
    assert boundary_result.findings[0].message_key == "boundary.forbidden_call"


def test_repeated_calls_have_distinct_fingerprints() -> None:
    task = make_source(
        "app/task.py",
        """
from app.database import get_async_session
from sqlalchemy.ext.asyncio import AsyncSession

async def run(session: AsyncSession) -> None:
    get_async_session()
    get_async_session()
    await session.commit()
    await session.commit()
""".strip(),
    )

    result = _run(
        task,
        roles={"task": ("app/task.py",)},
        allowed_imports={"task": frozenset({"task"})},
        owners=frozenset({"service"}),
        session_providers=frozenset({"app.database.get_async_session"}),
    )
    relevant = tuple(
        finding
        for finding in result.findings
        if finding.rule_id in {RuleId("SESSION001"), RuleId("TX001")}
    )

    assert len(relevant) == 4
    assert len({finding.fingerprint for finding in relevant}) == 4


def test_import_direction_and_cycle_rules_find_confirmed_violations() -> None:
    router = make_source("app/router.py", "from app.model import value")
    model = make_source("app/model.py", "from app.router import route")

    result = _run(
        router,
        model,
        roles={"router": ("app/router.py",), "model": ("app/model.py",)},
        allowed_imports={
            "router": frozenset({"service"}),
            "model": frozenset({"model"}),
        },
    )

    assert any(
        item.rule_id == RuleId("ARCH001") and item.verdict is RuleVerdict.FAIL
        for item in result.evaluations
    )
    assert any(
        item.rule_id == RuleId("ARCH002") and item.verdict is RuleVerdict.FAIL
        for item in result.evaluations
    )


def test_unresolved_risky_call_without_resolver_candidates_is_not_applicable() -> None:
    source = make_source("app/service.py", "now()")

    result = _run(
        source,
        roles={"service": ("app/**",)},
        allowed_imports={"service": frozenset({"service"})},
    )
    time_result = next(item for item in result.evaluations if item.rule_id == RuleId("TIME001"))

    assert time_result.verdict is RuleVerdict.NOT_APPLICABLE


def test_raw_time_access_is_allowed_only_inside_registered_wrapper_definition() -> None:
    source = make_source(
        "app/clock.py",
        """
from datetime import datetime
def utc_now():
    return datetime.now()
""".strip(),
    )
    wrapper = CatalogEntry(
        SymbolId("app.clock.utc_now"),
        frozenset({Effect("time.now")}),
        AccessPath.APPROVED_WRAPPER,
    )

    result = _run(
        source,
        roles={"service": ("app/**",)},
        allowed_imports={"service": frozenset({"service"})},
        entries=(wrapper,),
    )
    relevant = tuple(
        item
        for item in result.evaluations
        if item.rule_id == RuleId("TIME001") and item.verdict is RuleVerdict.PASS
    )

    assert len(relevant) == 1


def test_unrelated_unresolved_calls_are_not_applicable() -> None:
    source = make_source("app/service.py", "send_message()")

    result = _run(
        source,
        roles={"service": ("app/**",)},
        allowed_imports={"service": frozenset({"service"})},
    )
    time_result = next(item for item in result.evaluations if item.rule_id == RuleId("TIME001"))

    assert time_result.verdict is RuleVerdict.NOT_APPLICABLE


def test_unresolved_commit_without_resolver_candidates_is_not_applicable() -> None:
    source = make_source("app/service.py", "session.commit()")

    result = _run(
        source,
        roles={"service": ("app/**",)},
        allowed_imports={"service": frozenset({"service"})},
        owners=frozenset({"service"}),
        boundary_policy=_strict_boundary_policy(),
    )
    tx_result = next(item for item in result.evaluations if item.rule_id == RuleId("TX001"))

    assert tx_result.verdict is RuleVerdict.NOT_APPLICABLE


def test_unresolved_business_rollback_is_not_a_database_transaction() -> None:
    source = make_source("app/service.py", "prompt_service.rollback()")

    result = _run(
        source,
        roles={"service": ("app/**",)},
        allowed_imports={"service": frozenset({"service"})},
        owners=frozenset({"service"}),
        boundary_policy=_strict_boundary_policy(),
    )
    tx_result = next(item for item in result.evaluations if item.rule_id == RuleId("TX001"))

    assert tx_result.verdict is RuleVerdict.NOT_APPLICABLE


def test_unresolved_rollback_without_resolver_candidates_is_not_applicable() -> None:
    source = make_source(
        "app/database.py",
        """
async def get_async_session():
    await session.rollback()
""".strip(),
    )

    result = _run(
        source,
        roles={"database": ("app/database.py",)},
        allowed_imports={"database": frozenset({"database"})},
        owners=frozenset({"service"}),
        session_providers=frozenset({"app.database.get_async_session"}),
    )
    tx_result = next(item for item in result.evaluations if item.rule_id == RuleId("TX001"))

    assert tx_result.verdict is RuleVerdict.NOT_APPLICABLE


def test_cycle_cannot_be_exempted_by_zone() -> None:
    first = make_source("app/a.py", "from app.b import value")
    second = make_source("app/b.py", "from app.a import value")
    snapshot = analyze(first, second)
    context = make_context(
        snapshot,
        roles={"service": ("app/**",)},
        allowed_imports={"service": frozenset({"service"})},
    )
    result = PolicyEngine(builtin_rule_registry()).run(context)
    cycle_result = next(item for item in result.evaluations if item.rule_id == RuleId("ARCH002"))

    assert cycle_result.verdict is RuleVerdict.FAIL


def test_import_rule_rejects_local_and_relative_imports() -> None:
    local = make_source(
        "app/service.py",
        "def run():\n    from vendor.optional import load\n    return load()",
    )
    relative = make_source("app/other.py", "from .service import run")

    result = _run(
        local,
        relative,
        roles={"service": ("app/**",)},
        allowed_imports={"service": frozenset({"service"})},
    )
    evaluations = tuple(item for item in result.evaluations if item.rule_id == RuleId("IMPORT001"))

    assert (
        next(
            item for item in evaluations if item.target.module_id == ModuleId("app.service")
        ).verdict
        is RuleVerdict.FAIL
    )
    assert (
        next(item for item in evaluations if item.target.module_id == ModuleId("app.other")).verdict
        is RuleVerdict.FAIL
    )


def test_import_rule_reports_one_finding_for_one_from_import_statement() -> None:
    source = make_source(
        "app/service.py",
        "def run():\n    from vendor.optional import load, save\n    return load(), save()",
    )

    result = _run(
        source,
        roles={"service": ("app/**",)},
        allowed_imports={"service": frozenset({"service"})},
    )
    findings = tuple(
        finding for finding in result.findings if finding.rule_id == RuleId("IMPORT001")
    )

    assert len(findings) == 1


def test_module_level_type_checking_import_is_not_a_local_import() -> None:
    source = make_source(
        "app/service.py",
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    from app.model import Model\n"
        "\n"
        "def run(value: 'Model'):\n"
        "    return value",
    )

    result = _run(
        source,
        roles={"service": ("app/**",)},
        allowed_imports={"service": frozenset({"service"})},
    )

    assert not [finding for finding in result.findings if finding.rule_id == RuleId("IMPORT001")]


def test_import_rule_allows_optional_and_cycle_avoiding_local_imports() -> None:
    optional = make_source(
        "app/optional.py",
        "def load():\n"
        "    try:\n"
        "        import optional_sdk\n"
        "    except ImportError:\n"
        "        return None\n"
        "    return optional_sdk",
    )
    first = make_source("app/first.py", "from app.second import run\ndef helper():\n    return 1")
    second = make_source(
        "app/second.py",
        "def run():\n    from app.first import helper\n    return helper()",
    )

    result = _run(
        optional,
        first,
        second,
        roles={"service": ("app/**",)},
        allowed_imports={"service": frozenset({"service"})},
    )

    assert not [finding for finding in result.findings if finding.rule_id == RuleId("IMPORT001")]


def test_import_rule_keeps_unexplained_local_imports_active() -> None:
    source = make_source(
        "app/service.py",
        "def load():\n"
        "    try:\n"
        "        import required_sdk\n"
        "    except ValueError:\n"
        "        return None\n"
        "    return required_sdk",
    )
    result = _run(
        source,
        roles={"service": ("app/**",)},
        allowed_imports={"service": frozenset({"service"})},
    )

    findings = [finding for finding in result.findings if finding.rule_id == RuleId("IMPORT001")]
    assert len(findings) == 1


def test_size_rule_uses_the_stricter_role_limit() -> None:
    source = make_source("app/service.py", "first = 1\nsecond = 2\nthird = 3")

    result = _run(
        source,
        roles={"service": ("app/**",)},
        allowed_imports={"service": frozenset({"service"})},
        max_lines_by_role={"service": 2},
    )
    size_result = next(item for item in result.evaluations if item.rule_id == RuleId("SIZE001"))

    assert size_result.verdict is RuleVerdict.FAIL
    assert size_result.findings[0].arguments["maximum"] == 2


def test_responsibility_boundaries_separate_service_contract_and_adapter_roles() -> None:
    service = make_source("app/service.py", "import vendor_sdk")
    contract = make_source("app/contract.py", "from fastapi import Request")
    adapter = make_source(
        "app/adapter.py",
        "from sqlalchemy.ext.asyncio import AsyncSession\n"
        "async def run(session: AsyncSession):\n    await session.execute('select 1')",
    )

    result = _run(
        service,
        contract,
        adapter,
        roles={
            "service": ("app/service.py",),
            "contract": ("app/contract.py",),
            "adapter": ("app/adapter.py",),
        },
        allowed_imports={
            "service": frozenset({"service"}),
            "contract": frozenset({"contract"}),
            "adapter": frozenset({"adapter"}),
        },
        boundary_policy=_boundary_policy(),
    )

    assert {finding.rule_id for finding in result.findings} >= {
        RuleId("BOUNDARY002"),
        RuleId("BOUNDARY003"),
        RuleId("ADAPTER001"),
    }


def test_http_rule_requires_timeout_on_configured_client_construction() -> None:
    missing = make_source("app/missing.py", "import httpx\nhttpx.AsyncClient()")
    configured = make_source("app/configured.py", "import httpx\nhttpx.AsyncClient(timeout=10.0)")

    result = _run(
        missing,
        configured,
        roles={"adapter": ("app/**",)},
        allowed_imports={"adapter": frozenset({"adapter"})},
        boundary_policy=_boundary_policy(),
    )
    evaluations = tuple(item for item in result.evaluations if item.rule_id == RuleId("HTTP001"))

    assert (
        next(
            item for item in evaluations if item.target.module_id == ModuleId("app.missing")
        ).verdict
        is RuleVerdict.FAIL
    )
    assert (
        next(
            item for item in evaluations if item.target.module_id == ModuleId("app.configured")
        ).verdict
        is RuleVerdict.PASS
    )


def test_log_rule_requires_approved_context_around_external_call() -> None:
    unwrapped = make_source("app/unwrapped.py", "import httpx\nhttpx.get('https://example.test')")
    wrapped = make_source(
        "app/wrapped.py",
        "import httpx\n"
        "from app.logging import external_call\n"
        "with external_call():\n    httpx.get('https://example.test')",
    )

    result = _run(
        unwrapped,
        wrapped,
        roles={"adapter": ("app/**",)},
        allowed_imports={"adapter": frozenset({"adapter"})},
        boundary_policy=_boundary_policy(),
    )
    evaluations = tuple(item for item in result.evaluations if item.rule_id == RuleId("LOG001"))

    assert (
        next(
            item for item in evaluations if item.target.module_id == ModuleId("app.unwrapped")
        ).verdict
        is RuleVerdict.FAIL
    )
    assert (
        next(
            item for item in evaluations if item.target.module_id == ModuleId("app.wrapped")
        ).verdict
        is RuleVerdict.PASS
    )


def test_log_rule_accepts_configured_callable_that_owns_external_call() -> None:
    source = make_source(
        "app/client.py",
        "import httpx\ndef logged_request():\n    return httpx.get('https://example.test')",
    )
    boundary_policy = replace(
        _boundary_policy(),
        external_call_wrappers=frozenset({SymbolId("app.client.logged_request")}),
    )

    result = _run(
        source,
        roles={"adapter": ("app/**",)},
        allowed_imports={"adapter": frozenset({"adapter"})},
        boundary_policy=boundary_policy,
    )
    evaluation = next(item for item in result.evaluations if item.rule_id == RuleId("LOG001"))

    assert evaluation.verdict is RuleVerdict.PASS


def test_dto_and_snapshot_rules_find_deep_mutability_and_wrong_placement() -> None:
    source = make_source(
        "app/dtos/report.py",
        """
from dataclasses import dataclass
from pydantic import BaseModel

@dataclass
class ReportDto:
    tags: list[str]

class ReportSnapshot(BaseModel):
    title: str
""".strip(),
    )

    result = _run(
        source,
        roles={"dto": ("app/dtos/**",)},
        allowed_imports={"dto": frozenset({"dto"})},
        code_policy=_code_policy(),
    )

    assert {finding.rule_id for finding in result.findings} >= {
        RuleId("DTO001"),
        RuleId("DTO002"),
        RuleId("SNAPSHOT001"),
    }
    assert len([finding for finding in result.findings if finding.rule_id == RuleId("DTO001")]) == 3


def test_snapshot_rule_versions_root_contract_not_nested_component_models() -> None:
    source = make_source(
        "app/snapshots/report_snapshot.py",
        """from pydantic import BaseModel

class ReportTotals(BaseModel):
    total: int

class ReportSnapshotV1(BaseModel):
    totals: ReportTotals
""",
    )

    result = _run(
        source,
        roles={"snapshot": ("app/snapshots/**",)},
        allowed_imports={"snapshot": frozenset({"snapshot"})},
        code_policy=_code_policy(),
    )

    assert not [finding for finding in result.findings if finding.rule_id == RuleId("SNAPSHOT001")]


def test_dto_rule_accepts_frozen_pydantic_contract_and_rejects_mutable_one() -> None:
    source = make_source(
        "app/dtos/order.py",
        """from pydantic import BaseModel, ConfigDict

class FrozenResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    value: tuple[str, ...]

class MutableResult(BaseModel):
    value: str
""",
    )
    result = _run(
        source,
        roles={"dto": ("app/dtos/**",)},
        allowed_imports={"dto": frozenset({"dto"})},
        code_policy=_code_policy(),
    )

    findings = [finding for finding in result.findings if finding.rule_id == RuleId("DTO001")]
    assert len(findings) == 1
    assert findings[0].enclosing_symbol == SymbolId("app.dtos.order.MutableResult")


def test_configured_dto_base_activates_contract_outside_dto_module_role() -> None:
    base = make_source(
        "app/contracts.py",
        """from pydantic import BaseModel, ConfigDict
class BaseResult(BaseModel):
    model_config = ConfigDict(frozen=True)
""",
    )
    concrete = make_source(
        "app/feature.py",
        "from app.contracts import BaseResult\nclass Payload(BaseResult): value: str",
    )
    result = _run(
        base,
        concrete,
        roles={"application": ("app/**",)},
        allowed_imports={"application": frozenset({"application"})},
        code_policy=replace(
            _code_policy(),
            dto_base_symbols=frozenset({SymbolId("app.contracts.BaseResult")}),
        ),
    )

    assert not [finding for finding in result.findings if finding.rule_id == RuleId("DTO001")]
    assert len([finding for finding in result.findings if finding.rule_id == RuleId("DTO002")]) == 1


def test_schema_and_api_rules_read_config_fields_and_endpoint_decorators() -> None:
    schema = make_source(
        "app/schemas/user.py",
        """
from pydantic import BaseModel

class CreateRequest(BaseModel):
    name: str

class UserResponse(BaseModel):
    name: str

class UserDetailResponse(UserResponse):
    email: str

class UnsafeResponse(BaseModel):
    @classmethod
    def from_internal(cls, data):
        return cls(**data)
""".strip(),
    )
    router = make_source(
        "app/apis/user.py",
        """
from fastapi import APIRouter
from app.schemas.user import UserResponse
router = APIRouter()

@router.post("/users")
async def create_user():
    return UserResponse(name="Ada")
""".strip(),
    )

    result = _run(
        schema,
        router,
        roles={"schema": ("app/schemas/**",), "router": ("app/apis/**",)},
        allowed_imports={
            "schema": frozenset({"schema"}),
            "router": frozenset({"router", "schema"}),
        },
        code_policy=_code_policy(),
    )

    assert {finding.rule_id for finding in result.findings} >= {
        RuleId("SCHEMA001"),
        RuleId("SCHEMA002"),
        RuleId("SCHEMA003"),
        RuleId("API001"),
        RuleId("API002"),
    }


def test_enum_relationship_db_enum_and_timezone_rules_are_explicit() -> None:
    enum = make_source(
        "app/core/enums/status.py",
        'from enum import StrEnum\nclass StatusEnum(StrEnum):\n    active = "ACTIVE"',
    )
    model = make_source(
        "app/models/item.py",
        """
from sqlalchemy import DateTime, Enum as SQLEnum
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from app.core.enums.status import StatusEnum

class Base(DeclarativeBase): pass
class Item(Base):
    __tablename__ = "item"
    id: Mapped[int] = mapped_column(primary_key=True)
    status: Mapped[StatusEnum] = mapped_column(SQLEnum(StatusEnum))
    created_at: Mapped[object] = mapped_column(DateTime())
    items: Mapped[list["Item"]] = relationship()
""".strip(),
    )

    result = _run(
        enum,
        model,
        roles={"core": ("app/core/**",), "model": ("app/models/**",)},
        allowed_imports={
            "core": frozenset({"core"}),
            "model": frozenset({"model", "core"}),
        },
        code_policy=_code_policy(),
    )

    assert {finding.rule_id for finding in result.findings} >= {
        RuleId("ENUM001"),
        RuleId("ORM001"),
        RuleId("ORM002"),
        RuleId("DB001"),
    }


def test_enum_rule_requires_str_enum_unless_the_class_is_registered() -> None:
    enum = make_source(
        "app/core/enums/code.py",
        """
from enum import Enum, IntEnum

class Mode(Enum):
    ACTIVE = "active"

class NumericCode(IntEnum):
    OK = 1
""".strip(),
    )
    code_policy = replace(
        _code_policy(),
        non_str_enum_exceptions=frozenset({SymbolId("app.core.enums.code.NumericCode")}),
    )

    result = _run(
        enum,
        roles={"core": ("app/core/**",)},
        allowed_imports={"core": frozenset({"core"})},
        code_policy=code_policy,
    )

    enum_findings = tuple(
        finding for finding in result.findings if finding.rule_id == RuleId("ENUM001")
    )
    assert [finding.message_key for finding in enum_findings] == ["enum.base_type"]


def test_private_enum_cannot_be_imported_by_another_module() -> None:
    state = make_source(
        "app/internal/state.py",
        'from enum import StrEnum\nclass _State(StrEnum):\n    READY = "ready"',
    )
    consumer = make_source(
        "app/service.py",
        "from app.internal.state import _State\nvalue = _State.READY",
    )

    result = _run(
        state,
        consumer,
        roles={"core": ("app/**",)},
        allowed_imports={"core": frozenset({"core"})},
        code_policy=_code_policy(),
    )

    enum_findings = tuple(
        finding for finding in result.findings if finding.rule_id == RuleId("ENUM001")
    )
    assert [finding.message_key for finding in enum_findings] == ["enum.private_import"]


def test_runtime_rules_reject_dynamic_import_hidden_dispatch_and_open_session_call() -> None:
    source = make_source(
        "app/service.py",
        """
from importlib import import_module
import httpx
from app.database import get_async_session

async def run(client: httpx.AsyncClient):
    import_module("app.hidden")
    task.delay()
    async with get_async_session():
        await client.get("https://example.test")
""".strip(),
    )

    result = _run(
        source,
        roles={"service": ("app/**",)},
        allowed_imports={"service": frozenset({"service"})},
        owners=frozenset({"service"}),
        session_providers=frozenset({"app.database.get_async_session"}),
        boundary_policy=_boundary_policy(),
        code_policy=_code_policy(),
    )

    assert {finding.rule_id for finding in result.findings} >= {
        RuleId("IMPORT002"),
        RuleId("TX002"),
    }


def test_external_call_rule_recognizes_tortoise_atomic_decorator() -> None:
    source = make_source(
        "app/service.py",
        "from tortoise.transactions import atomic\n"
        "import requests\n"
        "@atomic()\n"
        "def run():\n    return requests.get('https://example.test')\n",
    )
    boundaries = replace(
        _boundary_policy(),
        logged_external_calls=(SymbolId("requests.get"),),
    )

    result = _run(
        source,
        roles={"service": ("app/**",)},
        allowed_imports={"service": frozenset({"service"})},
        boundary_policy=boundaries,
        code_policy=_code_policy(),
    )

    assert RuleId("TX002") in {finding.rule_id for finding in result.findings}


def test_tx002_propagates_external_effect_through_project_owned_wrapper() -> None:
    external = make_source(
        "app/external.py",
        "import httpx\n"
        "async def post_product(client: httpx.AsyncClient):\n"
        "    return await client.post('https://example.test')",
    )
    service = make_source(
        "app/service.py",
        "from app.database import get_async_session\n"
        "from app.external import post_product\n"
        "async def run():\n"
        "    async with get_async_session():\n"
        "        await post_product()",
    )
    boundaries = replace(
        _boundary_policy(),
        logged_external_calls=(SymbolId("httpx.AsyncClient.post"),),
    )

    result = _run(
        external,
        service,
        roles={"adapter": ("app/external.py",), "service": ("app/service.py",)},
        allowed_imports={
            "adapter": frozenset({"adapter"}),
            "service": frozenset({"service", "adapter"}),
        },
        owners=frozenset({"service"}),
        session_providers=frozenset({"app.database.get_async_session"}),
        boundary_policy=boundaries,
        code_policy=_code_policy(),
    )

    findings = tuple(f for f in result.findings if f.rule_id == RuleId("TX002"))
    assert len(findings) == 1
    assert findings[0].enclosing_symbol == SymbolId("app.service.run")


def test_async001_propagates_blocking_effect_through_project_helper() -> None:
    helper = make_source(
        "app/helper.py",
        "import requests\ndef fetch():\n    return requests.get('https://example.test')",
    )
    service = make_source(
        "app/service.py",
        "from app.helper import fetch\nasync def run():\n    return fetch()",
    )

    result = _run(
        helper,
        service,
        roles={"service": ("app/**",)},
        allowed_imports={"service": frozenset({"service"})},
        boundary_policy=_boundary_policy(),
        code_policy=_code_policy(),
    )

    findings = tuple(f for f in result.findings if f.rule_id == RuleId("ASYNC001"))
    assert len(findings) == 1
    assert findings[0].enclosing_symbol == SymbolId("app.service.run")


def test_session002_propagates_session_open_through_project_helper() -> None:
    helper = make_source(
        "app/helper.py",
        "from app.database import get_async_session\n"
        "async def load():\n"
        "    async with get_async_session():\n"
        "        return None",
    )
    service = make_source(
        "app/service.py",
        "from app.database import get_async_session\n"
        "from app.helper import load\n"
        "async def run():\n"
        "    async with get_async_session():\n"
        "        return await load()",
    )

    result = _run(
        helper,
        service,
        roles={"service": ("app/**",)},
        allowed_imports={"service": frozenset({"service"})},
        owners=frozenset({"service"}),
        session_providers=frozenset({"app.database.get_async_session"}),
        boundary_policy=_boundary_policy(),
        code_policy=_code_policy(),
    )

    findings = tuple(f for f in result.findings if f.rule_id == RuleId("SESSION002"))
    assert len(findings) == 1
    assert findings[0].enclosing_symbol == SymbolId("app.service.run")


def test_schema003_propagates_bulk_mapping_through_project_helper() -> None:
    schema = make_source(
        "app/schema.py",
        "from pydantic import BaseModel\n"
        "def copy_fields(value: object) -> dict:\n"
        "    return value.model_dump()\n"
        "class UserResponse(BaseModel):\n"
        "    name: str\n"
        "    @classmethod\n"
        "    def from_internal(cls, value: object) -> 'UserResponse':\n"
        "        return cls(**copy_fields(value))",
    )

    result = _run(
        schema,
        roles={"schema": ("app/**",)},
        allowed_imports={"schema": frozenset({"schema"})},
        boundary_policy=_boundary_policy(),
        code_policy=_code_policy(),
    )

    findings = tuple(f for f in result.findings if f.rule_id == RuleId("SCHEMA003"))
    assert any(f.message_key == "schema.bulk_mapping" for f in findings)


def test_dto_rules_classify_pydantic_model_before_checking_its_name() -> None:
    dto = make_source(
        "app/dto.py",
        "from pydantic import BaseModel\nclass AgentPrompt(BaseModel):\n    values: list[str]",
    )

    result = _run(
        dto,
        roles={"dto": ("app/**",)},
        allowed_imports={"dto": frozenset({"dto"})},
        code_policy=_code_policy(),
    )

    dto_findings = {f.rule_id for f in result.findings}
    assert {RuleId("DTO001"), RuleId("DTO002")} <= dto_findings


def test_schema003_uses_fastapi_response_model_semantics_without_name_suffix() -> None:
    schema = make_source(
        "app/schema.py",
        "from pydantic import BaseModel\nclass UserView(BaseModel):\n    name: str",
    )
    router = make_source(
        "app/router.py",
        "from fastapi import APIRouter\n"
        "from app.schema import UserView\n"
        "router = APIRouter()\n"
        "@router.get('/', response_model=UserView)\n"
        "async def get_user():\n"
        "    return UserView(name='Ada')",
    )

    result = _run(
        schema,
        router,
        roles={"schema": ("app/schema.py",), "router": ("app/router.py",)},
        allowed_imports={
            "schema": frozenset({"schema"}),
            "router": frozenset({"router", "schema"}),
        },
        code_policy=_code_policy(),
    )

    findings = tuple(f for f in result.findings if f.rule_id == RuleId("SCHEMA003"))
    assert {f.message_key for f in findings} == {
        "schema.mapper_missing",
        "schema.router_direct_mapping",
    }


def test_exception_registry_rule_checks_missing_duplicate_and_unused_codes() -> None:
    base = make_source("app/errors.py", "class AppException(Exception):\n    pass")
    codes = make_source(
        "app/codes.py",
        """
from enum import StrEnum
class ErrorCode(StrEnum):
    FIRST = "first"
    UNUSED = "unused"
""".strip(),
    )
    errors = make_source(
        "app/auth_errors.py",
        """
from app.codes import ErrorCode
from app.errors import AppException

class FirstError(AppException):
    code = ErrorCode.FIRST

class DuplicateError(AppException):
    code = ErrorCode.FIRST

class MissingError(AppException):
    pass
""".strip(),
    )

    result = _run(
        base,
        codes,
        errors,
        roles={"core": ("app/**",)},
        allowed_imports={"core": frozenset({"core"})},
        code_policy=_code_policy(),
    )

    exception_findings = tuple(
        finding for finding in result.findings if finding.rule_id == RuleId("EXC001")
    )
    assert {finding.message_key for finding in exception_findings} == {
        "exception.code_duplicate",
        "exception.code_missing",
        "exception.code_unused",
    }


def test_exception_registry_rejects_a_new_unregistered_exception_family() -> None:
    base = make_source("app/errors.py", "class AppException(Exception):\n    pass")
    other = make_source("app/other.py", "class DeliveryError(Exception):\n    pass")
    codes = make_source(
        "app/codes.py",
        "from enum import StrEnum\nclass ErrorCode(StrEnum):\n    RESERVED = 'reserved'",
    )
    code_policy = replace(
        _code_policy(),
        reserved_error_code_symbols=frozenset({SymbolId("app.codes.ErrorCode.RESERVED")}),
    )

    result = _run(
        base,
        other,
        codes,
        roles={"core": ("app/**",)},
        allowed_imports={"core": frozenset({"core"})},
        code_policy=code_policy,
    )

    findings = tuple(f for f in result.findings if f.rule_id == RuleId("EXC001"))
    assert any(
        f.enclosing_symbol == SymbolId("app.other.DeliveryError")
        and f.message_key == "exception.family_unregistered"
        for f in findings
    )


def test_strict_shape_and_api_examples_pass_all_new_contract_rules() -> None:
    dto = make_source(
        "app/dtos/user.py",
        """
from dataclasses import dataclass

@dataclass(frozen=True)
class UserData:
    tags: tuple[str, ...]
""".strip(),
    )
    snapshot = make_source(
        "app/snapshots/report.py",
        """
from pydantic import BaseModel

class ReportSnapshotV1(BaseModel):
    title: str
""".strip(),
    )
    schema = make_source(
        "app/schemas/user.py",
        """
from pydantic import BaseModel, Field
from app.config import REQUEST_CONFIG, RESPONSE_CONFIG

class UserRequest(BaseModel):
    model_config = REQUEST_CONFIG
    name: str = Field(description="Name", examples=["Ada"])

class UserResponse(BaseModel):
    model_config = RESPONSE_CONFIG
    name: str = Field(description="Name", examples=["Ada"])

    @classmethod
    def from_internal(cls, data: object) -> "UserResponse":
        return cls(name=data.name)
""".strip(),
    )
    router = make_source(
        "app/apis/user.py",
        '''
from fastapi import APIRouter
from app.schemas.user import UserResponse

router = APIRouter()

@router.get("/users", response_model=UserResponse, responses={404: {}})
async def get_user() -> UserResponse:
    """Return one user."""
    return UserResponse.from_internal(data)
'''.strip(),
    )

    result = _run(
        dto,
        snapshot,
        schema,
        router,
        roles={
            "dto": ("app/dtos/**",),
            "snapshot": ("app/snapshots/**",),
            "schema": ("app/schemas/**",),
            "router": ("app/apis/**",),
        },
        allowed_imports={
            "dto": frozenset({"dto"}),
            "snapshot": frozenset({"snapshot"}),
            "schema": frozenset({"schema"}),
            "router": frozenset({"router", "schema"}),
        },
        code_policy=_code_policy(),
    )

    shape_rules = {
        RuleId("DTO001"),
        RuleId("DTO002"),
        RuleId("SNAPSHOT001"),
        RuleId("SCHEMA001"),
        RuleId("SCHEMA002"),
        RuleId("SCHEMA003"),
        RuleId("API001"),
        RuleId("API002"),
    }
    assert not [finding for finding in result.findings if finding.rule_id in shape_rules]


def test_generic_schema_base_does_not_require_request_or_response_config() -> None:
    schema = make_source(
        "app/schemas/base.py",
        """
from pydantic import BaseModel, ConfigDict

class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
""".strip(),
    )
    code_policy = replace(
        _code_policy(),
        generic_schema_bases=frozenset({SymbolId("app.schemas.base.BaseSchema")}),
    )

    result = _run(
        schema,
        roles={"schema": ("app/schemas/**",)},
        allowed_imports={"schema": frozenset({"schema"})},
        code_policy=code_policy,
    )

    assert not [finding for finding in result.findings if finding.rule_id == RuleId("SCHEMA001")]


def test_endpoint_without_body_may_omit_response_model() -> None:
    router = make_source(
        "app/apis/user.py",
        '''
from fastapi import APIRouter, Response

router = APIRouter()

@router.delete("/users", status_code=204, responses={404: {}})
async def delete_user() -> Response:
    """Delete one user."""
    return Response(status_code=204)
'''.strip(),
    )

    result = _run(
        router,
        roles={"router": ("app/apis/**",)},
        allowed_imports={"router": frozenset({"router"})},
        code_policy=_code_policy(),
    )

    assert not [finding for finding in result.findings if finding.rule_id == RuleId("API001")]


def test_endpoint_metadata_helper_is_resolved_without_executing_it() -> None:
    router = make_source(
        "app/apis/items.py",
        '''from fastapi import APIRouter
router = APIRouter()

class ItemResponse: pass

def base_endpoint_docs():
    return {"responses": {404: {}}, "response_model": ItemResponse}

def endpoint_docs():
    return base_endpoint_docs()

@router.get("/items", **endpoint_docs())
async def list_items() -> ItemResponse:
    """List items."""
    return ItemResponse()
''',
    )
    result = _run(
        router,
        roles={"router": ("app/apis/**",)},
        allowed_imports={"router": frozenset({"router"})},
        code_policy=_code_policy(),
    )

    assert not [finding for finding in result.findings if finding.rule_id == RuleId("API001")]


def test_response_mapper_name_is_configurable_but_bulk_copy_remains_forbidden() -> None:
    schema = make_source(
        "app/schemas/user.py",
        """from pydantic import BaseModel

class UserResponse(BaseModel):
    @classmethod
    def from_result(cls, result: object) -> "UserResponse":
        notify(**{"kind": "user"})
        return cls(name=result.name)

class UnsafeResponse(BaseModel):
    @classmethod
    def from_result(cls, result: object) -> "UnsafeResponse":
        return cls.model_validate(result.model_dump())
""",
    )
    result = _run(
        schema,
        roles={"schema": ("app/schemas/**",)},
        allowed_imports={"schema": frozenset({"schema"})},
        code_policy=replace(_code_policy(), response_mapper_name="from_result"),
    )

    findings = [finding for finding in result.findings if finding.rule_id == RuleId("SCHEMA003")]
    assert [finding.message_key for finding in findings] == [
        "schema.bulk_mapping",
        "schema.bulk_mapping",
    ]


def test_multi_write_atomicity_propagates_first_party_helpers_and_accepts_decorator() -> None:
    model = make_source(
        "app/models/user.py",
        "from tortoise.models import Model\nclass User(Model): pass",
    )
    repository = make_source(
        "app/repositories/user.py",
        """from app.models.user import User
async def create_first():
    await User.create(name="first")
async def create_second():
    await User.create(name="second")
""",
    )
    service = make_source(
        "app/services/user.py",
        """from tortoise.transactions import atomic
from app.repositories.user import create_first, create_second
async def unsafe():
    await create_first()
    await create_second()
@atomic()
async def safe():
    await create_first()
    await create_second()
""",
    )
    result = _run(
        model,
        repository,
        service,
        roles={
            "model": ("app/models/**",),
            "repository": ("app/repositories/**",),
            "service": ("app/services/**",),
        },
        allowed_imports={
            "model": frozenset({"model"}),
            "repository": frozenset({"repository", "model"}),
            "service": frozenset({"service", "repository"}),
        },
        code_policy=_code_policy(),
    )

    findings = [finding for finding in result.findings if finding.rule_id == RuleId("TX003")]
    assert [finding.enclosing_symbol for finding in findings] == [
        SymbolId("app.services.user.unsafe")
    ]


def test_tx003_does_not_treat_plain_session_lifetime_as_atomic_transaction() -> None:
    model = make_source(
        "app/model.py",
        "from tortoise.models import Model\nclass User(Model): pass",
    )
    service = make_source(
        "app/service.py",
        "from app.database import get_session\n"
        "from app.model import User\n"
        "async def update():\n"
        "    async with get_session():\n"
        "        await User.create(name='first')\n"
        "        await User.create(name='second')",
    )

    result = _run(
        model,
        service,
        roles={"model": ("app/model.py",), "service": ("app/service.py",)},
        allowed_imports={
            "model": frozenset({"model"}),
            "service": frozenset({"service", "model"}),
        },
        owners=frozenset({"service"}),
        session_providers=frozenset({"app.database.get_session"}),
        code_policy=_code_policy(),
    )

    assert any(f.rule_id == RuleId("TX003") for f in result.findings)


def test_tx003_accepts_explicit_atomic_transaction_context() -> None:
    model = make_source(
        "app/model.py",
        "from tortoise.models import Model\nclass User(Model): pass",
    )
    service = make_source(
        "app/service.py",
        "from app.database import atomic_session\n"
        "from app.model import User\n"
        "async def update():\n"
        "    async with atomic_session():\n"
        "        await User.create(name='first')\n"
        "        await User.create(name='second')",
    )

    result = _run(
        model,
        service,
        roles={"model": ("app/model.py",), "service": ("app/service.py",)},
        allowed_imports={
            "model": frozenset({"model"}),
            "service": frozenset({"service", "model"}),
        },
        owners=frozenset({"service"}),
        boundary_contexts=frozenset({"app.database.atomic_session"}),
        code_policy=_code_policy(),
    )

    assert not any(f.rule_id == RuleId("TX003") for f in result.findings)


def test_wiring_rule_propagates_adapter_construction_through_factory_functions() -> None:
    adapter = make_source(
        "app/adapter.py",
        "class MailAdapter: pass\ndef build_mail():\n    return MailAdapter()",
    )
    service = make_source(
        "app/service.py",
        "from app.adapter import build_mail\ndef run():\n    return build_mail()",
    )
    boundaries = replace(
        _strict_boundary_policy(),
        adapter_roles=frozenset({Role("adapter")}),
        bootstrap_roles=frozenset({Role("bootstrap")}),
    )

    result = _run(
        adapter,
        service,
        roles={"adapter": ("app/adapter.py",), "service": ("app/service.py",)},
        allowed_imports={
            "adapter": frozenset({"adapter"}),
            "service": frozenset({"service", "adapter"}),
        },
        boundary_policy=boundaries,
        code_policy=_code_policy(),
    )

    findings = tuple(f for f in result.findings if f.rule_id == RuleId("WIRING001"))
    assert any(f.enclosing_symbol == SymbolId("app.service.run") for f in findings)


def test_orm_rules_do_not_match_unrelated_project_calls_by_method_name() -> None:
    model = make_source(
        "app/model.py",
        "class Builder:\n"
        "    @staticmethod\n"
        "    def relationship(): return None\n"
        "    @staticmethod\n"
        "    def DateTime(): return None\n"
        "relation = Builder.relationship()\n"
        "created = Builder.DateTime()",
    )

    result = _run(
        model,
        roles={"model": ("app/**",)},
        allowed_imports={"model": frozenset({"model"})},
        code_policy=_code_policy(),
    )

    assert not any(f.rule_id in {RuleId("ORM001"), RuleId("DB001")} for f in result.findings)


def test_known_external_effects_require_logging_without_repeating_logged_calls() -> None:
    source = make_source(
        "app/client.py",
        "import requests\ndef load():\n    return requests.get('https://example.test', timeout=5)",
    )
    boundaries = replace(_boundary_policy(), logged_external_calls=())

    result = _run(
        source,
        roles={"adapter": ("app/**",)},
        allowed_imports={"adapter": frozenset({"adapter"})},
        boundary_policy=boundaries,
    )

    assert any(f.rule_id == RuleId("LOG001") for f in result.findings)


def test_api_rules_cover_api_route_programmatic_routes_and_parameter_metadata() -> None:
    source = make_source(
        "app/router.py",
        "from fastapi import APIRouter, Header\n"
        "router = APIRouter(tags=['users'])\n"
        "@router.api_route('/decorated', methods=['GET'])\n"
        "async def decorated(token: str = Header()): return {}\n"
        "def programmatic(): return {}\n"
        "router.add_api_route('/programmatic', programmatic, methods=['GET'])",
    )

    result = _run(
        source,
        roles={"router": ("app/**",)},
        allowed_imports={"router": frozenset({"router"})},
        code_policy=_code_policy(),
    )

    api1 = tuple(f for f in result.findings if f.rule_id == RuleId("API001"))
    api3 = tuple(f for f in result.findings if f.rule_id == RuleId("API003"))
    assert any(f.enclosing_symbol == SymbolId("app.router.decorated") for f in api1)
    assert any(f.enclosing_symbol == SymbolId("app.router.programmatic") for f in api1)
    assert any(f.message_key == "api.parameter_description_missing" for f in api3)


def test_strict_persistence_examples_pass_orm_rules() -> None:
    enum = make_source(
        "app/core/enums/status.py",
        'from enum import StrEnum\nclass Status(StrEnum):\n    ACTIVE = "active"',
    )
    model = make_source(
        "app/models/item.py",
        """
from sqlalchemy import DateTime, Enum as SQLEnum
from sqlalchemy.orm import relationship
from app.core.enums.status import Status

native_status = SQLEnum(
    Status,
    name="status",
    values_callable=lambda enum: [item.value for item in enum],
    native_enum=True,
)
portable_status = SQLEnum(
    Status,
    name="portable_status",
    values_callable=lambda enum: [item.value for item in enum],
    native_enum=False,
    create_constraint=True,
)
created_at = DateTime(timezone=True)
items = relationship(lazy="raise_on_sql")
""".strip(),
    )
    code_policy = replace(
        _code_policy(),
        native_enum_false_exceptions=frozenset({SymbolId("app.core.enums.status.Status")}),
    )

    result = _run(
        enum,
        model,
        roles={"core": ("app/core/**",), "model": ("app/models/**",)},
        allowed_imports={
            "core": frozenset({"core"}),
            "model": frozenset({"model", "core"}),
        },
        code_policy=code_policy,
    )

    persistence_rules = {
        RuleId("ENUM001"),
        RuleId("ORM001"),
        RuleId("ORM002"),
        RuleId("DB001"),
    }
    assert not [finding for finding in result.findings if finding.rule_id in persistence_rules]


def test_database_enum_exception_matches_original_symbol_through_re_export() -> None:
    enum = make_source(
        "app/core/enums/status.py",
        'from enum import StrEnum\nclass Status(StrEnum):\n    ACTIVE = "active"',
    )
    facade = make_source(
        "app/core/enums/__init__.py",
        "from .status import Status",
    )
    model = make_source(
        "app/models/item.py",
        "from sqlalchemy import Enum as SQLEnum\n"
        "from app.core.enums import Status\n"
        "status = SQLEnum(Status, name='status', "
        "values_callable=lambda enum: [item.value for item in enum], "
        "native_enum=False, create_constraint=False)",
    )
    code_policy = replace(
        _code_policy(),
        native_enum_false_exceptions=frozenset({SymbolId("app.core.enums.status.Status")}),
        native_enum_no_constraint_exceptions=frozenset({SymbolId("app.core.enums.status.Status")}),
    )

    result = _run(
        enum,
        facade,
        model,
        roles={"core": ("app/core/**",), "model": ("app/models/**",)},
        allowed_imports={
            "core": frozenset({"core"}),
            "model": frozenset({"model", "core"}),
        },
        code_policy=code_policy,
    )

    assert not [finding for finding in result.findings if finding.rule_id == RuleId("ORM002")]


def test_exception_registry_reports_unregistered_and_duplicate_names() -> None:
    base = make_source("app/errors.py", "class AppException(Exception):\n    pass")
    codes = make_source(
        "app/codes.py",
        'from enum import StrEnum\nclass ErrorCode(StrEnum):\n    FIRST = "first"',
    )
    first = make_source(
        "app/first.py",
        "from app.codes import ErrorCode\nfrom app.errors import AppException\n"
        "class SameError(AppException):\n    code = ErrorCode.FIRST",
    )
    second = make_source(
        "app/second.py",
        'from app.errors import AppException\nclass SameError(AppException):\n    code = "raw"',
    )

    result = _run(
        base,
        codes,
        first,
        second,
        roles={"core": ("app/**",)},
        allowed_imports={"core": frozenset({"core"})},
        code_policy=_code_policy(),
    )

    messages = {
        finding.message_key for finding in result.findings if finding.rule_id == RuleId("EXC001")
    }
    assert messages == {"exception.code_unregistered", "exception.name_duplicate"}


def test_exception_registry_accepts_error_code_passed_to_base_constructor() -> None:
    base = make_source("app/errors.py", "class AppException(Exception):\n    pass")
    codes = make_source(
        "app/codes.py",
        'from enum import StrEnum\nclass ErrorCode(StrEnum):\n    FIRST = "first"',
    )
    concrete = make_source(
        "app/concrete.py",
        "from app.codes import ErrorCode\n"
        "from app.errors import AppException\n"
        "class FirstError(AppException):\n"
        "    def __init__(self):\n"
        "        super().__init__(error_code=ErrorCode.FIRST, message='failed')",
    )

    result = _run(
        base,
        codes,
        concrete,
        roles={"core": ("app/**",)},
        allowed_imports={"core": frozenset({"core"})},
        code_policy=_code_policy(),
    )

    assert not [finding for finding in result.findings if finding.rule_id == RuleId("EXC001")]


def test_exception_names_are_unique_within_each_configured_family() -> None:
    source = make_source(
        "app/errors.py",
        """from enum import StrEnum
class ErrorCode(StrEnum):
    FIRST = "first"
    SECOND = "second"
class DomainError(Exception): pass
class TransportError(Exception): pass
""",
    )
    policy = replace(
        _code_policy(),
        exception_base_symbols=frozenset(
            {SymbolId("app.errors.DomainError"), SymbolId("app.errors.TransportError")}
        ),
    )
    # Give the two concrete classes the same public name in distinct modules/families.
    domain = make_source(
        "app/domain.py",
        "from app.errors import DomainError, ErrorCode\n"
        "class SameError(DomainError): code = ErrorCode.FIRST",
    )
    transport = make_source(
        "app/transport.py",
        "from app.errors import TransportError, ErrorCode\n"
        "class SameError(TransportError): code = ErrorCode.SECOND",
    )
    result = _run(
        source,
        domain,
        transport,
        roles={"core": ("app/**",)},
        allowed_imports={"core": frozenset({"core"})},
        code_policy=policy,
    )

    duplicate_names = [
        finding
        for finding in result.findings
        if finding.rule_id == RuleId("EXC001") and finding.message_key == "exception.name_duplicate"
    ]
    assert duplicate_names == []


def test_exception_registry_counts_direct_production_error_code_reference_as_used() -> None:
    base = make_source("app/errors.py", "class AppException(Exception):\n    pass")
    codes = make_source(
        "app/codes.py",
        "from enum import StrEnum\n"
        "class ErrorCode(StrEnum):\n"
        "    FIRST = 'first'\n"
        "    INTERNAL = 'internal'",
    )
    concrete = make_source(
        "app/concrete.py",
        "from app.codes import ErrorCode\n"
        "from app.errors import AppException\n"
        "class FirstError(AppException):\n"
        "    code = ErrorCode.FIRST",
    )
    handler = make_source(
        "app/handler.py",
        "from app.codes import ErrorCode\nresponse_code = ErrorCode.INTERNAL",
    )

    result = _run(
        base,
        codes,
        concrete,
        handler,
        roles={"core": ("app/**",)},
        allowed_imports={"core": frozenset({"core"})},
        code_policy=_code_policy(),
    )

    assert not [finding for finding in result.findings if finding.rule_id == RuleId("EXC001")]


def test_exception_registry_ignores_domain_exception_test_doubles() -> None:
    base = make_source("app/errors.py", "class AppException(Exception):\n    pass")
    test_double = make_source(
        "tests/test_errors.py",
        "from app.errors import AppException\nclass FakeError(AppException):\n    pass",
    )
    snapshot = analyze(base, test_double)
    context = make_context(
        snapshot,
        roles={"core": ("app/**",), "test": ("tests/**",)},
        zones={"test": ("tests/**",)},
        allowed_imports={
            "core": frozenset({"core"}),
            "test": frozenset({"test", "core"}),
        },
        code_policy=_code_policy(),
    )

    result = PolicyEngine(builtin_rule_registry()).run(context)

    assert not [finding for finding in result.findings if finding.rule_id == RuleId("EXC001")]


def test_strict_layer_boundaries_reject_each_wrong_responsibility() -> None:
    router = make_source(
        "app/router.py",
        "from fastapi import Depends, HTTPException\n"
        "from app.database import get_async_session\n"
        "def run(session=Depends(get_async_session)):\n"
        "    raise HTTPException(status_code=409)",
    )
    service = make_source(
        "app/service.py",
        "from sqlalchemy import select\n"
        "async def run(session):\n    await session.execute(select(object))",
    )
    query = make_source(
        "app/query.py",
        "from sqlalchemy import update\n"
        "async def run(session):\n    await session.execute(update(object))",
    )
    model = make_source("app/model.py", "import vendor_sdk\nvalue = vendor_sdk.fetch()")

    result = _run(
        router,
        service,
        query,
        model,
        roles={
            "router": ("app/router.py",),
            "service": ("app/service.py",),
            "query": ("app/query.py",),
            "model": ("app/model.py",),
        },
        allowed_imports={
            "router": frozenset({"router"}),
            "service": frozenset({"service"}),
            "query": frozenset({"query"}),
            "model": frozenset({"model"}),
        },
        owners=frozenset({"service"}),
        session_providers=frozenset({"app.database.get_async_session"}),
        boundary_policy=_strict_boundary_policy(),
    )

    strict_rules = {
        RuleId("ENTRY001"),
        RuleId("SERVICE001"),
        RuleId("QUERY001"),
        RuleId("MODEL001"),
    }
    assert {finding.rule_id for finding in result.findings}.issuperset(strict_rules)


def test_session_dependency_and_raw_sql_guards_close_remaining_static_gaps() -> None:
    service = make_source(
        "app/service.py",
        "from app.database import get_async_session\n"
        "from fastapi import Depends\n"
        "from sqlalchemy.ext.asyncio import AsyncSession\n"
        "async def run(session: AsyncSession, client=Depends()):\n"
        "    async with get_async_session():\n"
        "        async with get_async_session():\n"
        "            pass",
    )
    model = make_source(
        "app/model.py",
        "from sqlalchemy import text\nstatement = text('SELECT * FROM users')",
    )

    result = _run(
        service,
        model,
        roles={"service": ("app/service.py",), "model": ("app/model.py",)},
        allowed_imports={
            "service": frozenset({"service"}),
            "model": frozenset({"model"}),
        },
        owners=frozenset({"service"}),
        session_providers=frozenset({"app.database.get_async_session"}),
        boundary_policy=_strict_boundary_policy(),
    )

    assert {finding.rule_id for finding in result.findings}.issuperset(
        {
            RuleId("SESSION002"),
            RuleId("SESSION003"),
            RuleId("DEPENDS001"),
            RuleId("SQL001"),
        }
    )


def test_implementation_and_settings_are_constructed_only_at_startup_boundaries() -> None:
    adapter = make_source("app/adapter.py", "class PaymentAdapter:\n    pass")
    service = make_source(
        "app/service.py",
        "from app.adapter import PaymentAdapter\n"
        "from app.settings import Settings\n"
        "adapter = PaymentAdapter()\nsettings = Settings()",
    )
    bootstrap = make_source(
        "app/bootstrap.py",
        "from app.adapter import PaymentAdapter\n"
        "from app.settings import Settings\n"
        "adapter = PaymentAdapter()\nsettings = Settings()",
    )

    result = _run(
        adapter,
        service,
        bootstrap,
        roles={
            "adapter": ("app/adapter.py",),
            "service": ("app/service.py",),
            "bootstrap": ("app/bootstrap.py",),
        },
        allowed_imports={
            "adapter": frozenset({"adapter"}),
            "service": frozenset({"service", "adapter"}),
            "bootstrap": frozenset({"bootstrap", "adapter"}),
        },
        boundary_policy=_strict_boundary_policy(),
    )

    wiring = tuple(finding for finding in result.findings if finding.rule_id == RuleId("WIRING001"))
    settings = tuple(
        finding for finding in result.findings if finding.rule_id == RuleId("CONFIG001")
    )
    assert len(wiring) == 1
    assert len(settings) == 1
    assert wiring[0].primary_location.path.value == "app/service.py"
    assert settings[0].primary_location.path.value == "app/service.py"


def test_approved_factory_may_construct_adapter_implementation() -> None:
    adapter = make_source("app/adapter.py", "class PaymentAdapter:\n    pass")
    factory = make_source(
        "app/factory.py",
        "from app.adapter import PaymentAdapter\ndef build():\n    return PaymentAdapter()",
    )
    policy = replace(
        _strict_boundary_policy(),
        implementation_construction_roles=frozenset({Role("factory")}),
    )

    result = _run(
        adapter,
        factory,
        roles={"adapter": ("app/adapter.py",), "factory": ("app/factory.py",)},
        allowed_imports={
            "adapter": frozenset({"adapter"}),
            "factory": frozenset({"factory", "adapter"}),
        },
        boundary_policy=policy,
    )

    assert not [finding for finding in result.findings if finding.rule_id == RuleId("WIRING001")]


def test_adapter_support_value_is_not_treated_as_implementation() -> None:
    adapter = make_source(
        "app/adapter.py",
        "class PaymentError:\n    pass\n\ndef translate():\n    return PaymentError()",
    )
    policy = replace(
        _strict_boundary_policy(),
        adapter_implementation_suffixes=("Adapter", "Client", "Gateway", "Harness"),
    )

    result = _run(
        adapter,
        roles={"adapter": ("app/adapter.py",)},
        allowed_imports={"adapter": frozenset({"adapter"})},
        boundary_policy=policy,
    )

    assert not [finding for finding in result.findings if finding.rule_id == RuleId("WIRING001")]


def test_adapter_public_signature_cannot_expose_vendor_types() -> None:
    adapter = make_source(
        "app/adapter.py",
        "from vendor_sdk import Request, Response\n"
        "async def send(request: Request) -> Response:\n    return Response()",
    )

    result = _run(
        adapter,
        roles={"adapter": ("app/adapter.py",)},
        allowed_imports={"adapter": frozenset({"adapter"})},
        boundary_policy=_strict_boundary_policy(),
    )

    findings = tuple(
        finding for finding in result.findings if finding.rule_id == RuleId("ADAPTER002")
    )
    assert len(findings) == 1


def test_api_metadata_rule_reads_parameter_default_calls() -> None:
    router = make_source(
        "app/router.py",
        "from fastapi import APIRouter, Query\n"
        "router = APIRouter()\n"
        "@router.get('/')\n"
        "async def list_items(page: int = Query(1)):\n    return []",
    )

    result = _run(
        router,
        roles={"router": ("app/router.py",)},
        allowed_imports={"router": frozenset({"router"})},
        code_policy=_code_policy(),
    )

    messages = {
        finding.message_key for finding in result.findings if finding.rule_id == RuleId("API003")
    }
    assert messages == {"api.query_description_missing", "api.router_tags_missing"}


def test_api_metadata_rule_accepts_tags_on_router_registration() -> None:
    router = make_source(
        "app/router.py",
        "from fastapi import APIRouter, Query\n"
        "router = APIRouter()\n"
        "@router.get('/')\n"
        "async def list_items(page: int = Query(1, description='Page')):\n    return []",
    )
    bootstrap = make_source(
        "app/bootstrap.py",
        "from fastapi import FastAPI\n"
        "from app.router import router\n"
        "app = FastAPI()\n"
        "app.include_router(router, tags=['items'])",
    )

    result = _run(
        router,
        bootstrap,
        roles={
            "router": ("app/router.py",),
            "bootstrap": ("app/bootstrap.py",),
        },
        allowed_imports={
            "router": frozenset({"router"}),
            "bootstrap": frozenset({"bootstrap", "router"}),
        },
        code_policy=_code_policy(),
    )

    assert not any(finding.rule_id == RuleId("API003") for finding in result.findings)


def test_api_metadata_rule_rejects_registration_without_tags() -> None:
    router = make_source(
        "app/router.py",
        "from fastapi import APIRouter, Query\n"
        "router = APIRouter()\n"
        "@router.get('/')\n"
        "async def list_items(page: int = Query(1, description='Page')):\n    return []",
    )
    bootstrap = make_source(
        "app/bootstrap.py",
        "from fastapi import FastAPI\n"
        "from app.router import router\n"
        "app = FastAPI()\n"
        "app.include_router(router)",
    )

    result = _run(
        router,
        bootstrap,
        roles={
            "router": ("app/router.py",),
            "bootstrap": ("app/bootstrap.py",),
        },
        allowed_imports={
            "router": frozenset({"router"}),
            "bootstrap": frozenset({"bootstrap", "router"}),
        },
        code_policy=_code_policy(),
    )

    findings = tuple(finding for finding in result.findings if finding.rule_id == RuleId("API003"))
    assert len(findings) == 1
    assert findings[0].message_key == "api.router_tags_missing"


def test_test_policy_rejects_nested_conftest_and_typed_raw_http_client() -> None:
    nested = make_source("tests/unit/conftest.py", "VALUE = 1")
    raw = make_source(
        "tests/test_api.py",
        "import httpx\n"
        "async def test_list(client: httpx.AsyncClient):\n"
        "    await client.get('/items')",
    )
    snapshot = analyze(nested, raw)
    code_policy = replace(
        _code_policy(),
        raw_test_http_calls=(SymbolId("httpx.AsyncClient.get"),),
        raw_test_http_client_constructors=(SymbolId("httpx.AsyncClient"),),
    )
    context = make_context(
        snapshot,
        roles={"test": ("tests/**",)},
        zones={"test": ("tests/**",)},
        allowed_imports={"test": frozenset({"test"})},
        code_policy=code_policy,
    )
    result = PolicyEngine(builtin_rule_registry()).run(context)

    assert {finding.rule_id for finding in result.findings}.issuperset(
        {RuleId("TEST001"), RuleId("TEST002")}
    )


def test_test_http_fixture_role_may_construct_shared_client() -> None:
    fixture = make_source(
        "tests/fixtures.py",
        "import httpx\ndef build_client():\n    return httpx.AsyncClient()",
    )
    code_policy = replace(
        _code_policy(),
        raw_test_http_client_constructors=(SymbolId("httpx.AsyncClient"),),
        test_http_fixture_roles=frozenset({Role("test_fixture")}),
    )
    snapshot = analyze(fixture)
    context = make_context(
        snapshot,
        roles={"test_fixture": ("tests/fixtures.py",)},
        zones={"test": ("tests/**",)},
        allowed_imports={"test_fixture": frozenset({"test_fixture"})},
        code_policy=code_policy,
    )
    result = PolicyEngine(builtin_rule_registry()).run(context)

    assert not [finding for finding in result.findings if finding.rule_id == RuleId("TEST002")]


def test_test_http_client_use_requires_proven_approved_fixture_origin() -> None:
    fixture = make_source(
        "tests/conftest.py",
        """import httpx
import pytest

@pytest.fixture
def api_client():
    return httpx.AsyncClient()
""",
    )
    test = make_source(
        "tests/test_api.py",
        """import httpx

async def test_list(api_client: httpx.AsyncClient):
    await api_client.get("/items")
""",
    )
    code_policy = replace(
        _code_policy(),
        raw_test_http_calls=(SymbolId("httpx.AsyncClient.get"),),
        raw_test_http_client_constructors=(SymbolId("httpx.AsyncClient"),),
        test_http_fixture_roles=frozenset({Role("test_fixture")}),
    )
    context = make_context(
        analyze(fixture, test),
        roles={
            "test_fixture": ("tests/conftest.py",),
            "test": ("tests/test_*.py",),
        },
        zones={"test": ("tests/**",)},
        allowed_imports={
            "test_fixture": frozenset({"test_fixture"}),
            "test": frozenset({"test", "test_fixture"}),
        },
        code_policy=code_policy,
    )
    result = PolicyEngine(builtin_rule_registry()).run(context)

    assert not [finding for finding in result.findings if finding.rule_id == RuleId("TEST002")]


def test_raw_sql_allows_fixed_schema_expression_and_approved_wrapper_only() -> None:
    model = make_source(
        "app/model.py",
        "from sqlalchemy import text\n"
        "from sqlalchemy.orm import mapped_column\n"
        "value = mapped_column(server_default=text('0'))",
    )
    raw_query = make_source(
        "app/raw_query.py",
        "from sqlalchemy import text\n"
        "def execute_named(*, name, statement, parameters):\n"
        "    return text(statement)\n"
        "\n"
        "def load():\n"
        "    return execute_named(\n"
        "        name='users.by_id',\n"
        "        statement='SELECT * FROM users WHERE id = :id',\n"
        "        parameters={'id': 1},\n"
        "    )",
    )
    service = make_source(
        "app/service.py",
        "from sqlalchemy import text\nstatement = text('SELECT 1')",
    )
    policy = replace(
        _strict_boundary_policy(),
        raw_query_roles=frozenset({Role("raw_query")}),
        raw_query_wrappers=frozenset({SymbolId("app.raw_query.execute_named")}),
        schema_sql_roles=frozenset({Role("model")}),
        schema_sql_argument_names=("server_default",),
        raw_sql_execution_methods=("exec_driver_sql", "execute"),
    )

    result = _run(
        model,
        raw_query,
        service,
        roles={
            "model": ("app/model.py",),
            "raw_query": ("app/raw_query.py",),
            "service": ("app/service.py",),
        },
        allowed_imports={
            "model": frozenset({"model"}),
            "raw_query": frozenset({"raw_query"}),
            "service": frozenset({"service"}),
        },
        boundary_policy=policy,
    )

    sql_findings = [finding for finding in result.findings if finding.rule_id == RuleId("SQL001")]
    assert len(sql_findings) == 1
    assert sql_findings[0].primary_location.path.value == "app/service.py"


def test_raw_query_wrapper_requires_approved_role_name_fixed_statement_and_parameters() -> None:
    wrapper = make_source(
        "app/raw_query.py",
        "def execute_named(*, name, statement, parameters):\n    return statement",
    )
    repository = make_source(
        "app/repository.py",
        "from app.raw_query import execute_named\n"
        "def load(table):\n"
        "    execute_named(name='users.all', statement=f'SELECT * FROM {table}', parameters={})\n"
        "    execute_named(name='users.count', statement='SELECT count(*) FROM users')",
    )
    service = make_source(
        "app/service.py",
        "from app.raw_query import execute_named\n"
        "def load():\n"
        "    return execute_named(\n"
        "        name='users.all', statement='SELECT * FROM users', parameters={}\n"
        "    )",
    )
    policy = replace(
        _strict_boundary_policy(),
        raw_query_roles=frozenset({Role("repository")}),
        raw_query_wrappers=frozenset({SymbolId("app.raw_query.execute_named")}),
    )

    result = _run(
        wrapper,
        repository,
        service,
        roles={
            "raw_query": ("app/raw_query.py",),
            "repository": ("app/repository.py",),
            "service": ("app/service.py",),
        },
        allowed_imports={
            "raw_query": frozenset({"raw_query"}),
            "repository": frozenset({"repository", "raw_query"}),
            "service": frozenset({"service", "raw_query"}),
        },
        boundary_policy=policy,
    )

    sql_findings = [finding for finding in result.findings if finding.rule_id == RuleId("SQL001")]
    assert len(sql_findings) == 3
    assert {finding.evidence[0].value for finding in sql_findings} == {
        "statement:not_fixed",
        "missing:parameters",
        "role:service",
    }


def test_raw_sql_rejects_dynamic_schema_expression_and_direct_string_execution() -> None:
    model = make_source(
        "app/model.py",
        "from sqlalchemy import text\n"
        "from sqlalchemy.orm import mapped_column\n"
        "DEFAULT = '0'\nvalue = mapped_column(server_default=text(f'{DEFAULT}'))",
    )
    repository = make_source(
        "app/repository.py",
        "async def run(session, db_session):\n"
        "    await session.execute(f'SELECT {table_name}')\n"
        "    await db_session.execute('SELECT 1')\n"
        "    await session.execute('SELECT ' + table_name)\n"
        "    await session.execute('SELECT {}'.format(table_name))",
    )
    policy = replace(
        _strict_boundary_policy(),
        schema_sql_roles=frozenset({Role("model")}),
        schema_sql_argument_names=("server_default",),
        raw_sql_execution_methods=("exec_driver_sql", "execute"),
    )

    result = _run(
        model,
        repository,
        roles={"model": ("app/model.py",), "repository": ("app/repository.py",)},
        allowed_imports={
            "model": frozenset({"model"}),
            "repository": frozenset({"repository"}),
        },
        boundary_policy=policy,
    )

    sql_findings = [finding for finding in result.findings if finding.rule_id == RuleId("SQL001")]
    assert len(sql_findings) == 1


def test_session_participant_contract_distinguishes_helpers_and_owners() -> None:
    service = make_source(
        "app/service.py",
        "from sqlalchemy.ext.asyncio import AsyncSession\n"
        "def transaction_participant(fn):\n    return fn\n\n"
        "class Producer:\n    async def commit(self):\n        return None\n\n"
        "async def _load(session: AsyncSession):\n    return 1\n\n"
        "async def participating(session: AsyncSession):\n    return 1\n\n"
        "async def harmless(session: AsyncSession, producer: Producer):\n"
        "    await producer.commit()\n\n"
        "@transaction_participant\n"
        "async def decorated(session: AsyncSession):\n    return 1\n\n"
        "async def unsafe(session: AsyncSession):\n    await session.commit()",
    )
    approvals = (
        PolicyApproval(
            RuleId("SESSION003"),
            SymbolId("app.service.participating"),
            "public transaction participant",
            target="sqlalchemy.ext.asyncio.AsyncSession",
            kind="participant",
        ),
        PolicyApproval(
            RuleId("SESSION003"),
            SymbolId("app.service.unsafe"),
            "public transaction participant",
            target="sqlalchemy.ext.asyncio.AsyncSession",
            kind="participant",
        ),
        PolicyApproval(
            RuleId("SESSION003"),
            SymbolId("app.service.harmless"),
            "participant may commit a non-database producer",
            target="sqlalchemy.ext.asyncio.AsyncSession",
            kind="participant",
        ),
        PolicyApproval(
            RuleId("SESSION003"),
            SymbolId("app.service.transaction_participant"),
            "decorator marks transaction participants",
            target="sqlalchemy.ext.asyncio.AsyncSession",
            kind="participant",
        ),
    )
    result = _run(
        service,
        roles={"service": ("app/service.py",)},
        allowed_imports={"service": frozenset({"service"})},
        approvals=approvals,
        boundary_policy=_strict_boundary_policy(),
    )

    findings = [finding for finding in result.findings if finding.rule_id == RuleId("SESSION003")]
    assert len(findings) == 1
    assert findings[0].message_key == "session.participant_owns_transaction"
    assert findings[0].enclosing_symbol == SymbolId("app.service.unsafe")
    assert result.approval_keys == tuple(sorted(approval.key for approval in approvals))


def test_session_participant_role_applies_the_safe_default_contract() -> None:
    service = make_source(
        "app/service.py",
        "from sqlalchemy.ext.asyncio import AsyncSession\n"
        "async def safe(session: AsyncSession):\n    return 1\n"
        "async def unsafe(session: AsyncSession):\n    await session.commit()",
    )
    result = _run(
        service,
        roles={"service": ("app/service.py",)},
        allowed_imports={"service": frozenset({"service"})},
        participants=frozenset({"service"}),
        boundary_policy=_strict_boundary_policy(),
    )

    findings = [finding for finding in result.findings if finding.rule_id == RuleId("SESSION003")]
    assert len(findings) == 1
    assert findings[0].enclosing_symbol == SymbolId("app.service.unsafe")


def test_entry_roles_can_have_distinct_allowed_effect_kinds() -> None:
    worker = make_source("app/worker.py", "import httpx\nclient = httpx.AsyncClient()")
    policy = replace(
        _strict_boundary_policy(),
        entry_allowed_kinds=FrozenMap(((Role("task"), frozenset({"external"})),)),
    )
    result = _run(
        worker,
        roles={"task": ("app/worker.py",)},
        allowed_imports={"task": frozenset({"task"})},
        boundary_policy=policy,
    )

    assert not [finding for finding in result.findings if finding.rule_id == RuleId("ENTRY001")]


def test_adapter_scoped_client_factory_is_allowed_only_in_context_manager() -> None:
    adapter = make_source(
        "app/adapter.py",
        "import httpx\n"
        "async def scoped():\n"
        "    async with httpx.AsyncClient() as client:\n"
        "        return client\n"
        "client = httpx.AsyncClient()",
    )
    policy = replace(
        _strict_boundary_policy(),
        scoped_construction_roles=frozenset({Role("adapter")}),
    )
    result = _run(
        adapter,
        roles={"adapter": ("app/adapter.py",)},
        allowed_imports={"adapter": frozenset({"adapter"})},
        boundary_policy=policy,
    )

    findings = [finding for finding in result.findings if finding.rule_id == RuleId("WIRING001")]
    assert len(findings) == 1
    assert findings[0].primary_location.start_line == 4


def test_composition_can_register_fastapi_dependencies() -> None:
    composition = make_source(
        "app/composition.py",
        "from fastapi import Depends, FastAPI\n"
        "def auth():\n    return 1\n"
        "app = FastAPI(dependencies=[Depends(auth)])",
    )
    policy = replace(
        _strict_boundary_policy(),
        dependency_registration_roles=frozenset({Role("composition")}),
    )
    result = _run(
        composition,
        roles={"composition": ("app/composition.py",)},
        allowed_imports={"composition": frozenset({"composition"})},
        boundary_policy=policy,
    )

    assert not [finding for finding in result.findings if finding.rule_id == RuleId("DEPENDS001")]


def test_annotated_pydantic_field_metadata_is_recognized() -> None:
    schema = make_source(
        "app/schema.py",
        "from typing import Annotated\nfrom pydantic import BaseModel, Field\n"
        "class UserResponse(BaseModel):\n"
        "    name: Annotated[str, Field(description='name', examples=['Ada'])]",
    )
    result = _run(
        schema,
        roles={"schema": ("app/schema.py",)},
        allowed_imports={"schema": frozenset({"schema"})},
        code_policy=_code_policy(),
    )

    assert not [finding for finding in result.findings if finding.rule_id == RuleId("API002")]


def test_schema_index_sql_and_non_native_no_constraint_exception_are_supported() -> None:
    enum = make_source(
        "app/enums.py",
        "from enum import StrEnum\nclass Status(StrEnum):\n    ACTIVE = 'active'",
    )
    model = make_source(
        "app/model.py",
        "from sqlalchemy import Enum as SQLEnum, Index, text\n"
        "from app.enums import Status\n"
        "_ACTIVE = \"status = 'active'\"\n"
        "index = Index('ix_active', text(_ACTIVE))\n"
        "status = SQLEnum(Status, name='status', "
        "values_callable=lambda enum: [item.value for item in enum], "
        "native_enum=False, create_constraint=False)",
    )
    code = replace(
        _code_policy(),
        native_enum_false_exceptions=frozenset({SymbolId("app.enums.Status")}),
        native_enum_no_constraint_exceptions=frozenset({SymbolId("app.enums.Status")}),
    )
    boundaries = replace(
        _strict_boundary_policy(),
        schema_sql_roles=frozenset({Role("model")}),
        schema_sql_parent_calls=(SymbolId("sqlalchemy.Index"),),
    )
    result = _run(
        enum,
        model,
        roles={"core": ("app/enums.py",), "model": ("app/model.py",)},
        allowed_imports={
            "core": frozenset({"core"}),
            "model": frozenset({"model", "core"}),
        },
        boundary_policy=boundaries,
        code_policy=code,
    )

    assert not [
        finding
        for finding in result.findings
        if finding.rule_id in {RuleId("SQL001"), RuleId("ORM002")}
    ]


def test_rule_zone_can_exclude_test_only_lazy_import_rules() -> None:
    test_module = make_source(
        "tests/test_lazy.py",
        "def load():\n    import importlib\n    return importlib.import_module('optional')",
    )
    result = _run(
        test_module,
        roles={"test": ("tests/**",)},
        zones={"test": ("tests/**",)},
        rule_zones={"IMPORT001": frozenset({"prod"}), "IMPORT002": frozenset({"prod"})},
        allowed_imports={"test": frozenset({"test"})},
    )

    assert not [
        finding
        for finding in result.findings
        if finding.rule_id in {RuleId("IMPORT001"), RuleId("IMPORT002")}
    ]
