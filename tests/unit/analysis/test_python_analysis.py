from __future__ import annotations

import ast

import pytest
from tests.utils.builders import analyze, make_source

from taut.analysis.contracts import ContextManagerProvider, ResolverSettings
from taut.analysis.module_analysis import ModuleAnalysis
from taut.analysis.python.language_adapter import PythonAstAdapter
from taut.domain.facts import AnalysisStage, CompletenessState, ResolutionState
from taut.domain.ids import ModuleId, SymbolId


def test_python_adapter_resolves_aliases_annotations_and_decorators() -> None:
    source = make_source(
        "app/service.py",
        """
from datetime import datetime as dt
from sqlalchemy.ext.asyncio import AsyncSession
from app.decorators import transactional

@transactional
async def save(session: AsyncSession) -> None:
    created = dt.now()
    await session.commit()
""".strip(),
    )

    module = analyze(source).modules[ModuleId("app.service")]
    symbols = tuple(call.ref.symbol for call in module.calls)

    assert SymbolId("datetime.datetime.now") in symbols
    assert SymbolId("sqlalchemy.ext.asyncio.AsyncSession.commit") in symbols
    assert module.functions[0].is_async is True
    assert module.decorators[0].ref.symbol == SymbolId("app.decorators.transactional")
    assert module.completeness.state is CompletenessState.COMPLETE


def test_python_adapter_preserves_dynamic_and_unresolved_calls() -> None:
    source = make_source(
        "app/dynamic.py",
        """
def run(target, name):
    unknown()
    getattr(target, name)()
""".strip(),
    )

    calls = analyze(source).modules[ModuleId("app.dynamic")].calls

    states = {call.ref.state for call in calls}
    assert ResolutionState.UNRESOLVED in states
    assert ResolutionState.DYNAMIC in states


def test_python_adapter_records_function_local_import() -> None:
    source = make_source(
        "app/local.py",
        """
def run():
    from app.worker import execute
    return execute()
""".strip(),
    )

    module = analyze(source).modules[ModuleId("app.local")]

    assert module.imports[0].enclosing_symbol == SymbolId("app.local.run")
    assert module.calls[0].ref.symbol == SymbolId("app.worker.execute")


def test_python_adapter_registers_nested_function_inside_control_flow() -> None:
    source = make_source(
        "app/nested.py",
        """
def run(enabled: bool) -> str:
    if enabled:
        def normalize(value: str) -> str:
            return value.strip()
        return normalize(" value ")
    return ""
""".strip(),
    )

    module = analyze(source).modules[ModuleId("app.nested")]

    assert module.completeness.state is CompletenessState.COMPLETE
    assert {function.symbol_id for function in module.functions} == {
        SymbolId("app.nested.run"),
        SymbolId("app.nested.run.normalize"),
    }


def test_python_adapter_accepts_unicode_function_names() -> None:
    source = make_source(
        "tests/test_payment.py",
        "def test_결제_성공() -> None:\n    pass",
    )

    module = analyze(source).modules[ModuleId("tests.test_payment")]

    assert module.completeness.state is CompletenessState.COMPLETE
    assert module.functions[0].symbol_id == SymbolId("tests.test_payment.test_결제_성공")


def test_python_adapter_resolves_item_from_configured_context_manager() -> None:
    source = make_source(
        "app/task.py",
        """
from app.database import get_async_session

async def run() -> None:
    async with get_async_session() as session:
        await session.commit()
""".strip(),
    )
    resolver = ResolverSettings(
        context_manager_providers=(
            ContextManagerProvider(
                SymbolId("app.database.get_async_session"),
                SymbolId("sqlalchemy.ext.asyncio.AsyncSession"),
            ),
        )
    )

    module = analyze(source, resolver=resolver).modules[ModuleId("app.task")]

    assert module.calls[-1].ref.symbol == SymbolId("sqlalchemy.ext.asyncio.AsyncSession.commit")


def test_python_adapter_does_not_guess_unconfigured_context_manager_type() -> None:
    source = make_source(
        "app/task.py",
        """
from app.database import get_async_session

async def run() -> None:
    async with get_async_session() as session:
        await session.commit()
""".strip(),
    )

    module = analyze(source).modules[ModuleId("app.task")]

    assert module.calls[-1].ref.state is ResolutionState.UNRESOLVED


def test_syntax_error_becomes_failed_module_and_issue() -> None:
    snapshot = analyze(make_source("app/broken.py", "def broken(:\n    pass"))
    module = snapshot.modules[ModuleId("app.broken")]

    assert module.completeness.state is CompletenessState.FAILED
    assert snapshot.coverage.failed_modules == 1
    assert snapshot.issues[0].code == "PY_PARSE_001"


def test_module_analysis_allows_only_sequential_transitions() -> None:
    lifecycle = ModuleAnalysis()
    lifecycle.advance(AnalysisStage.PARSED)
    lifecycle.advance(AnalysisStage.INDEXED)

    assert lifecycle.stage is AnalysisStage.INDEXED

    with pytest.raises(ValueError, match="cannot move"):
        lifecycle.advance(AnalysisStage.FACTS_READY)
    lifecycle.fail()
    with pytest.raises(ValueError, match="cannot advance"):
        lifecycle.advance(AnalysisStage.FACTS_READY)


def test_python_adapter_resolves_constructor_assignment_and_plain_import() -> None:
    source = make_source(
        "app/client.py",
        """
import datetime
from vendor import Client

client = Client()
client.send()
datetime.datetime.now()
""".strip(),
    )

    calls = analyze(source).modules[ModuleId("app.client")].calls
    symbols = {call.ref.symbol for call in calls}

    assert SymbolId("vendor.Client.send") in symbols
    assert SymbolId("datetime.datetime.now") in symbols


def test_unexpected_adapter_failure_becomes_analysis_issue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(*args: object, **kwargs: object) -> ast.Module:
        del args, kwargs
        raise RuntimeError("broken parser")

    monkeypatch.setattr(ast, "parse", explode)
    source = make_source("app/a.py", "value = 1")

    result = PythonAstAdapter().analyze_module(source)

    assert result.facts.completeness.state is CompletenessState.FAILED
    assert result.issues[0].code == "PY_ANALYSIS_001"
    assert result.issues[0].location is not None
    assert "app/a.py" in result.issues[0].message


def test_parallel_analysis_matches_sequential_analysis() -> None:
    sources = tuple(make_source(f"app/module_{index}.py", f"value = {index}") for index in range(8))

    sequential = analyze(*sources)
    parallel = analyze(*sources, workers=2)

    assert parallel == sequential


def test_python_adapter_records_class_field_and_endpoint_structure() -> None:
    source = make_source(
        "app/api.py",
        '''
from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter()

class UserResponse(BaseModel):
    name: str = Field(description="Name", examples=["Ada"])

@router.get("/users", response_model=UserResponse, responses={404: {}})
async def get_user(limit: int = 10) -> UserResponse:
    """Return one user."""
    return UserResponse(name="Ada")
'''.strip(),
    )

    module = analyze(source).modules[ModuleId("app.api")]

    class_fact = module.classes[0]
    assert class_fact.bases[0].symbols == (SymbolId("pydantic.BaseModel"),)
    field = next(item for item in module.fields if item.name == "name")
    assert field.value is not None
    assert {argument.name for argument in field.value.arguments} == {
        "description",
        "examples",
    }
    function = module.functions[0]
    assert function.has_docstring is True
    assert function.parameters[0].has_default is True
    endpoint = next(
        item for item in module.decorators if item.decorated_symbol == function.symbol_id
    )
    assert endpoint.ref.symbol == SymbolId("fastapi.APIRouter.get")
    assert {argument.name for argument in endpoint.arguments} >= {"response_model", "responses"}
