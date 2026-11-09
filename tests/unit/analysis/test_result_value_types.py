from __future__ import annotations

import pytest
from tests.utils.builders import analyze, make_source

from taut.domain.facts import ResolutionState
from taut.domain.ids import ModuleId, SymbolId


def _calls(source: str) -> dict[str, tuple[ResolutionState, SymbolId | None]]:
    module = analyze(make_source("app/probe.py", source)).modules[ModuleId("app.probe")]
    return {call.ref.written_name: (call.ref.state, call.ref.symbol) for call in module.calls}


def test_http_response_and_json_values_do_not_inherit_request_identity() -> None:
    calls = _calls("""
import httpx

def inspect(client: httpx.Client):
    response = client.get('https://example.invalid')
    response.raise_for_status()
    response.cookies.get('session')
    body = response.json()
    body.get('error')
""")
    assert calls["client.get"][1] == SymbolId("httpx.Client.get")
    assert calls["response.raise_for_status"][1] == SymbolId("httpx.Response.raise_for_status")
    assert calls["response.cookies.get"][1] == SymbolId("httpx.Cookies.get")
    # JSON can contain any value. Do not invent a dict or a new HTTP operation.
    assert calls["body.get"] == (ResolutionState.UNRESOLVED, None)


def test_awaited_http_response_and_chained_response_have_real_types() -> None:
    calls = _calls("""
import httpx

async def inspect(client: httpx.AsyncClient):
    response = await client.get('https://example.invalid')
    response.json()

def chained():
    return httpx.Client().get('https://example.invalid').json()
""")
    assert calls["response.json"][1] == SymbolId("httpx.Response.json")
    assert calls["httpx.Client().get('https://example.invalid').json"][1] == SymbolId(
        "httpx.Response.json"
    )


def test_unawaited_async_call_does_not_become_a_response() -> None:
    calls = _calls("""
import httpx

def inspect(client: httpx.AsyncClient):
    pending = client.get('https://example.invalid')
    pending.json()
""")
    assert calls["pending.json"] == (ResolutionState.UNRESOLVED, None)


def test_process_results_and_pipe_handles_do_not_inherit_process_execution() -> None:
    calls = _calls("""
import subprocess

def inspect():
    result = subprocess.run(['unused'], capture_output=True, text=True)
    result.stdout.strip()
    process = subprocess.Popen(['unused'], stdout=subprocess.PIPE)
    process.stdout.close()
    process.wait()
""")
    assert calls["subprocess.run"][1] == SymbolId("subprocess.run")
    assert calls["result.stdout.strip"] == (ResolutionState.UNRESOLVED, None)
    assert calls["process.stdout.close"][1] == SymbolId("io.IOBase.close")
    assert calls["process.wait"][1] == SymbolId("subprocess.Popen.wait")


@pytest.mark.parametrize("factory", ["factory", "Client"])
def test_unknown_factory_result_is_unresolved_instead_of_a_guessed_instance(factory: str) -> None:
    calls = _calls(f"from vendor import {factory}\nvalue = {factory}()\nvalue.send()\n")
    assert calls["value.send"] == (ResolutionState.UNRESOLVED, None)


def test_known_and_project_defined_constructors_still_resolve() -> None:
    calls = _calls("""
from pathlib import Path

class Reader:
    def read(self):
        return ''

reader = Reader()
reader.read()
path = Path('unused')
path.read_text()
""")
    assert calls["reader.read"][1] == SymbolId("app.probe.Reader.read")
    assert calls["path.read_text"][1] == SymbolId("pathlib.Path.read_text")


def test_reassignment_clears_stale_inferred_receiver_type() -> None:
    calls = _calls("""
import httpx

def inspect(client: httpx.Client, unknown):
    response = client.get('https://example.invalid')
    response = unknown
    response.json()
""")
    assert calls["response.json"] == (ResolutionState.UNRESOLVED, None)


def test_branch_types_do_not_resolve_to_the_last_visited_branch() -> None:
    calls = _calls("""
import httpx
from pathlib import Path

def inspect(client: httpx.Client, flag):
    if flag:
        value = client.get('https://example.invalid')
    else:
        value = Path('unused')
    value.read()
""")
    assert calls["value.read"][0] is not ResolutionState.RESOLVED


def test_response_alias_and_context_manager_preserve_request_detection() -> None:
    calls = _calls("""
import httpx

def inspect():
    with httpx.Client(timeout=1) as client:
        response = client.get('https://example.invalid')
    alias = response
    alias.json()
""")
    assert calls["client.get"][1] == SymbolId("httpx.Client.get")
    assert calls["alias.json"][1] == SymbolId("httpx.Response.json")


def test_known_database_factory_preserves_real_connection_methods() -> None:
    calls = _calls("""
from tortoise import connections

async def inspect():
    connection = connections.get('default')
    await connection.execute_query('select 1')
""")
    assert calls["connection.execute_query"][1] == SymbolId(
        "tortoise.backends.base.client.BaseDBAsyncClient.execute_query"
    )


@pytest.mark.parametrize("request_factory", ["requests.get", "requests.Session().get"])
def test_requests_response_contract_is_separate_from_request_function(request_factory: str) -> None:
    calls = _calls(
        f"import requests\nresponse = {request_factory}('https://example.invalid')\nresponse.json()\n"
    )
    assert calls["response.json"][1] == SymbolId("requests.Response.json")
