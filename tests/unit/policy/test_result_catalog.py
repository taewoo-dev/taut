from __future__ import annotations

from tests.utils.builders import analyze, make_context, make_source

from taut.configuration.catalog import EffectResolutionState
from taut.configuration.effective_policy import BoundaryPolicy
from taut.domain.ids import ModuleId, RuleId, SymbolId
from taut.loading.config_loader import default_project_configuration
from taut.policy.engine import PolicyEngine
from taut.policy.rules import builtin_rule_registry


def test_local_response_and_result_operations_are_not_unknown_risky_calls() -> None:
    source = make_source(
        "app/probe.py",
        """
import httpx
import subprocess

def inspect(client: httpx.Client):
    response = client.get('https://example.invalid')
    response.json()
    response.raise_for_status()
    response.cookies.get('session')
    result = subprocess.CompletedProcess([], 0, stdout='done')
    result.check_returncode()
    result.stdout.strip()
    client.unknown_operation()
""",
    )
    context = make_context(
        analyze(source),
        roles={"adapter": ("app/*.py",)},
        security_policy=default_project_configuration().policy.security,
    )
    result = PolicyEngine(builtin_rule_registry()).run(context)
    catalog_findings = [item for item in result.findings if item.rule_id == RuleId("CAT001")]
    assert len(catalog_findings) == 1
    assert catalog_findings[0].evidence[0].value == "httpx.Client.unknown_operation"
    calls = context.model.module(ModuleId("app.probe")).calls
    constructor = next(
        call for call in calls if call.ref.written_name == "subprocess.CompletedProcess"
    )
    assert context.effect_of(constructor).state is EffectResolutionState.NO_EFFECTS


def test_real_requests_process_execution_and_pipe_io_remain_detected_in_async() -> None:
    source = make_source(
        "app/probe.py",
        """
import httpx
import subprocess

async def inspect(client: httpx.Client):
    response = client.get('https://example.invalid')
    response.read()
    response.json()
    result = subprocess.run(['unused'], capture_output=True, text=True)
    result.stdout.strip()
    process = subprocess.Popen(['unused'], stdout=subprocess.PIPE)
    process.stdout.close()
    process.wait()
""",
    )
    context = make_context(
        analyze(source),
        roles={"adapter": ("app/*.py",)},
        security_policy=default_project_configuration().policy.security,
        boundary_policy=BoundaryPolicy(logged_external_calls=(SymbolId("httpx"),)),
    )
    result = PolicyEngine(builtin_rule_registry()).run(context)
    blocking = [item for item in result.findings if item.rule_id == RuleId("ASYNC001")]
    assert len(blocking) == 6
    logged = [item for item in result.findings if item.rule_id == RuleId("LOG001")]
    assert {item.evidence[0].value for item in logged} == {"client.get", "response.read"}
    assert not [item for item in result.findings if item.rule_id == RuleId("CAT001")]
