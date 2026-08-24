from __future__ import annotations

import ast

import pytest
from tests.utils.builders import analyze, make_source

from taut.analysis.contracts import ContextManagerProvider, ResolverSettings
from taut.analysis.module_analysis import ModuleAnalysis
from taut.analysis.python.language_adapter import PythonAstAdapter
from taut.domain.facts import (
    AnalysisStage,
    CompletenessState,
    ExecutionPhase,
    GuardKind,
    ImportIntent,
    ResolutionState,
    ScopeKind,
    SyntaxPosition,
)
from taut.domain.ids import ModuleId, SymbolId
from taut.domain.relations import BindingKind


def test_function_local_assignment_shadows_module_binding() -> None:
    source = make_source(
        "app/shadow.py",
        """
value = external.value

def run() -> None:
    print(value)
    value = 1
""".strip(),
    )

    module = analyze(source).modules[ModuleId("app.shadow")]
    value_ref = next(
        reference for reference in module.references if reference.ref.written_name == "value"
    )
    assert value_ref.ref.state is ResolutionState.UNRESOLVED


def test_module_and_class_bodies_resolve_bindings_in_source_order() -> None:
    source = make_source(
        "app/order.py",
        """
before_module = service
from provider import service

class Handler:
    before_class = dependency
    dependency = service
""".strip(),
    )

    references = analyze(source).modules[ModuleId("app.order")].references
    service_refs = [item for item in references if item.ref.written_name == "service"]
    dependency_ref = next(item for item in references if item.ref.written_name == "dependency")

    assert service_refs[0].ref.state is ResolutionState.UNRESOLVED
    assert service_refs[1].ref.symbol == SymbolId("provider.service")
    assert dependency_ref.ref.state is ResolutionState.UNRESOLVED


def test_deferred_function_lookup_sees_later_module_binding() -> None:
    source = make_source(
        "app/deferred.py",
        "def run():\n    return service()\n\nfrom provider import service",
    )

    calls = analyze(source).modules[ModuleId("app.deferred")].calls

    assert calls[0].ref.symbol == SymbolId("provider.service")


def test_method_lookup_skips_class_namespace() -> None:
    source = make_source(
        "app/method.py",
        """
from provider import service

class Handler:
    service = local_service
    def run(self):
        return service()
""".strip(),
    )

    calls = analyze(source).modules[ModuleId("app.method")].calls

    assert calls[0].ref.symbol == SymbolId("provider.service")


def test_lambda_and_comprehension_have_stable_synthetic_scopes() -> None:
    source = make_source(
        "app/synthetic.py",
        "transform = lambda item: item\nvalues = [item for item in source]",
    )

    first = analyze(source).modules[ModuleId("app.synthetic")]
    second = analyze(source).modules[ModuleId("app.synthetic")]
    item_scopes = {
        item.enclosing_symbol for item in first.references if item.ref.written_name == "item"
    }

    assert first == second
    assert all(scope is not None for scope in item_scopes)
    assert {scope.value.rsplit(".", 1)[1].rsplit("_", 2)[0] for scope in item_scopes if scope} == {
        "__lambda",
        "__comprehension",
    }


def test_parameters_and_lambda_parameters_are_lexical_bindings() -> None:
    source = make_source(
        "app/parameters.py",
        "def run(value, *, flag=False):\n    return (lambda item: item)(value)\n",
    )
    module = analyze(source).modules[ModuleId("app.parameters")]

    run_value = next(
        reference for reference in module.references if reference.ref.written_name == "value"
    )
    assert run_value.ref.symbol == SymbolId("app.parameters.run.value")
    assert run_value.ref.state is ResolutionState.RESOLVED


def test_relations_cover_binding_forms_with_exact_kinds_and_stable_owners() -> None:
    source = make_source(
        "app/binding_forms.py",
        """
value = 0
annotated: int = 1
left = right = 2
head, *tail = values
for item in values:
    pass
with manager() as resource:
    pass
async def consume() -> None:
    async for async_item in values:
        pass
    async with manager() as async_resource:
        pass
try:
    pass
except* Error as star_error:
    pass
match value:
    case {"key": matched, **rest}:
        pass
    case [first, *remaining]:
        pass
    case Point(x=class_value):
        pass
    case (One(or_value) | Two(or_value)):
        pass
captured = (written := value)
transform = lambda argument: argument
items = [element for element in values]

def outer() -> None:
    routed = 1
    def inner() -> None:
        nonlocal routed
        routed = 2
        global exported
        exported = routed
""".strip(),
    )
    first = analyze(source).relations.bindings
    second = analyze(source).relations.bindings
    assert first == second

    by_name = {
        name: [item for item in first if item.local_name == name]
        for name in (
            "annotated",
            "left",
            "right",
            "head",
            "tail",
            "item",
            "resource",
            "async_item",
            "async_resource",
            "star_error",
            "matched",
            "rest",
            "first",
            "remaining",
            "class_value",
            "or_value",
            "written",
            "argument",
            "element",
            "routed",
            "exported",
        )
    }
    assert any(item.kind is BindingKind.ASSIGNMENT for item in by_name["annotated"])
    assert any(item.kind is BindingKind.ASSIGNMENT for item in by_name["left"])
    assert any(item.kind is BindingKind.ASSIGNMENT for item in by_name["right"])
    assert any(item.kind is BindingKind.ASSIGNMENT for item in by_name["head"])
    assert any(item.kind is BindingKind.ASSIGNMENT for item in by_name["tail"])
    assert by_name["item"][0].kind is BindingKind.LOOP
    assert by_name["resource"][0].kind is BindingKind.WITH_ITEM
    assert by_name["async_item"][0].kind is BindingKind.LOOP
    assert by_name["async_resource"][0].kind is BindingKind.WITH_ITEM
    assert by_name["star_error"][0].kind is BindingKind.EXCEPTION
    assert {item.kind for item in by_name["matched"]} == {BindingKind.PATTERN}
    assert by_name["rest"][0].kind is BindingKind.PATTERN
    assert by_name["remaining"][0].kind is BindingKind.PATTERN
    assert by_name["class_value"][0].kind is BindingKind.PATTERN
    assert by_name["or_value"][0].kind is BindingKind.PATTERN
    assert by_name["written"][0].kind is BindingKind.WALRUS
    assert by_name["argument"][0].kind is BindingKind.PARAMETER
    assert by_name["element"][0].kind is BindingKind.COMPREHENSION
    assert by_name["element"][0].lexical_owner is not None
    assert by_name["routed"][0].lexical_owner == SymbolId("app.binding_forms.outer")
    assert by_name["exported"][0].lexical_owner is None
    assert len({item.id for item in first}) == len(first)
    assert all(item.id.value for item in first)
    assert all(item.defining_fact_id == item.id for item in first)
    assert all(item.target.symbol is not None for item in first)
    assert all(
        item.target.symbol is not None
        and item.target.symbol.value.rsplit(".", 1)[-1] == item.local_name
        for item in first
    )
    assert all(item.context.lexical_owner == item.lexical_owner for item in first)
    assert all(item.location.path.value == "app/binding_forms.py" for item in first)
    assert all(item.location.start_line <= item.location.end_line for item in first)


def test_global_and_nonlocal_route_to_declaring_scope() -> None:
    source = make_source(
        "app/scopes.py",
        """
value = 1

def outer() -> None:
    value = 2
    def inner() -> None:
        nonlocal value
        value = 3
        global exported
        exported = value
""".strip(),
    )

    module = analyze(source).modules[ModuleId("app.scopes")]
    assert module.completeness.state is CompletenessState.COMPLETE


def test_conditional_reference_is_not_reported_as_unconditionally_resolved() -> None:
    source = make_source(
        "app/conditional.py",
        """
from provider import value

if feature_flag:
    consume(value)
""".strip(),
    )

    module = analyze(source).modules[ModuleId("app.conditional")]
    value_ref = next(
        reference for reference in module.references if reference.ref.written_name == "value"
    )
    assert value_ref.ref.state is ResolutionState.CONDITIONAL


@pytest.mark.parametrize(
    ("control_flow", "expected_state", "expected_candidates"),
    [
        (
            "if enabled:\n    from provider import value",
            ResolutionState.CONDITIONAL,
            (SymbolId("provider.value"),),
        ),
        (
            "if enabled:\n    from provider import value\nelse:\n    from provider import value",
            ResolutionState.RESOLVED,
            (),
        ),
        (
            "if enabled:\n    from alpha import value\nelse:\n    from beta import value",
            ResolutionState.AMBIGUOUS,
            (SymbolId("alpha.value"), SymbolId("beta.value")),
        ),
        (
            "for item in items:\n    from provider import value",
            ResolutionState.CONDITIONAL,
            (SymbolId("provider.value"),),
        ),
        (
            "while enabled:\n    from provider import value",
            ResolutionState.CONDITIONAL,
            (SymbolId("provider.value"),),
        ),
        (
            "try:\n    from alpha import value\nexcept Error:\n    from beta import value",
            ResolutionState.AMBIGUOUS,
            (SymbolId("alpha.value"), SymbolId("beta.value")),
        ),
        (
            "match item:\n    case 1:\n        from alpha import value\n"
            "    case _:\n        from beta import value",
            ResolutionState.AMBIGUOUS,
            (SymbolId("alpha.value"), SymbolId("beta.value")),
        ),
    ],
)
def test_control_flow_merges_binding_states(
    control_flow: str,
    expected_state: ResolutionState,
    expected_candidates: tuple[SymbolId, ...],
) -> None:
    source = make_source("app/flow.py", f"{control_flow}\nvalue()")

    call = analyze(source).modules[ModuleId("app.flow")].calls[-1]

    assert call.ref.state is expected_state
    assert call.ref.candidates == expected_candidates


def test_deferred_function_observes_final_module_flow_merge() -> None:
    source = make_source(
        "app/deferred_flow.py",
        """
def load():
    return value()

if enabled:
    from alpha import value
else:
    from beta import value
""".strip(),
    )

    call = analyze(source).modules[ModuleId("app.deferred_flow")].calls[0]

    assert call.ref.state is ResolutionState.AMBIGUOUS
    assert call.ref.candidates == (SymbolId("alpha.value"), SymbolId("beta.value"))


def test_global_binding_merges_in_declaring_module_scope() -> None:
    source = make_source(
        "app/global_flow.py",
        """
def load(enabled):
    global value
    if enabled:
        from alpha import value
    else:
        from beta import value
    return value()
""".strip(),
    )

    call = analyze(source).modules[ModuleId("app.global_flow")].calls[0]

    assert call.ref.state is ResolutionState.AMBIGUOUS
    assert call.ref.candidates == (SymbolId("alpha.value"), SymbolId("beta.value"))


def test_ambiguous_attribute_preserves_concrete_qualified_candidates() -> None:
    source = make_source(
        "app/attribute_flow.py",
        """
if enabled:
    from alpha import client
else:
    from beta import client
client.send()
""".strip(),
    )

    call = analyze(source).modules[ModuleId("app.attribute_flow")].calls[0]

    assert call.ref.state is ResolutionState.AMBIGUOUS
    assert call.ref.candidates == (SymbolId("alpha.client.send"), SymbolId("beta.client.send"))


def test_loop_else_binding_remains_conditional_because_break_can_skip_else() -> None:
    source = make_source(
        "app/loop_else.py",
        """
for item in items:
    if stop:
        break
else:
    from provider import value
value()
""".strip(),
    )

    call = analyze(source).modules[ModuleId("app.loop_else")].calls[-1]

    assert call.ref.state is ResolutionState.CONDITIONAL
    assert call.ref.candidates == (SymbolId("provider.value"),)


def test_try_finally_binding_is_definite_after_all_try_paths() -> None:
    source = make_source(
        "app/finally_flow.py",
        """
try:
    work()
except Error:
    recover()
finally:
    from provider import value
value()
""".strip(),
    )

    call = analyze(source).modules[ModuleId("app.finally_flow")].calls[-1]

    assert call.ref.state is ResolutionState.RESOLVED
    assert call.ref.symbol == SymbolId("provider.value")


def test_type_checking_bindings_are_visible_only_to_type_namespace() -> None:
    source = make_source(
        "app/type_flow.py",
        """
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app.models import User

def load(user: User) -> User:
    return User()
""".strip(),
    )

    module = analyze(source).modules[ModuleId("app.type_flow")]
    annotation_symbols = {
        symbol
        for parameter in module.functions[0].parameters
        if parameter.annotation is not None
        for symbol in parameter.annotation.symbols
    }

    assert SymbolId("app.models.User") in annotation_symbols
    assert module.calls[-1].ref.state is ResolutionState.UNRESOLVED


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
    assert module.imports[0].context.scope_kind is ScopeKind.FUNCTION
    assert module.imports[0].context.execution_phase is ExecutionPhase.DEFERRED
    assert module.calls[0].ref.symbol == SymbolId("app.worker.execute")


def test_python_adapter_marks_import_error_guarded_dependency_as_optional() -> None:
    source = make_source(
        "app/optional.py",
        "def load():\n"
        "    try:\n"
        "        from vendor_sdk import Client\n"
        "    except (ImportError, RuntimeError):\n"
        "        return None\n"
        "    return Client()",
    )

    module = analyze(source).modules[ModuleId("app.optional")]

    assert module.imports[0].intent is ImportIntent.OPTIONAL_DEPENDENCY


def test_python_adapter_recognizes_aliased_type_checking_guard() -> None:
    source = make_source(
        "app/types.py",
        "from typing import TYPE_CHECKING as TC\nif TC:\n    from app.models import User",
    )

    module = analyze(source).modules[ModuleId("app.types")]

    assert module.imports[-1].context.guard is GuardKind.TYPE_CHECKING_ONLY


def test_type_checking_guard_dominates_nested_condition() -> None:
    source = make_source(
        "app/types.py",
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    if enabled:\n"
        "        import app.models",
    )

    module = analyze(source).modules[ModuleId("app.types")]

    assert module.imports[-1].context.guard is GuardKind.TYPE_CHECKING_ONLY


def test_occurrence_context_tracks_decorator_base_default_annotation_and_arguments() -> None:
    source = make_source(
        "app/contexts.py",
        """
from app.lib import Base, deco, factory, Type

@deco(factory())
class Child(Base):
    pass

def run(value: Type = factory()) -> Type:
    return factory(value)
""".strip(),
    )

    snapshot = analyze(source)
    module = snapshot.modules[ModuleId("app.contexts")]
    positions = {reference.context.position for reference in module.references}

    assert SyntaxPosition.DECORATOR in positions
    assert SyntaxPosition.BASE in positions
    assert SyntaxPosition.DEFAULT in positions
    assert SyntaxPosition.ANNOTATION in positions
    assert SyntaxPosition.ARGUMENT in positions
    argument = next(
        edge
        for edge in snapshot.relations.use_edges
        if edge.context.position is SyntaxPosition.ARGUMENT
    )
    assert argument.context.parent_fact_id is not None
    assert argument.context.argument_position == 0


def test_project_relations_preserve_bindings_and_unresolved_uses() -> None:
    snapshot = analyze(
        make_source("app/a.py", "from app.b import run as execute\nexecute()\nmissing()"),
        make_source("app/b.py", "def run(): pass"),
    )

    binding = next(item for item in snapshot.relations.bindings if item.local_name == "execute")
    uses = tuple(
        edge for edge in snapshot.relations.use_edges if edge.module_id == ModuleId("app.a")
    )

    assert any(edge.binding_id == binding.id for edge in uses)
    assert any(edge.ref.state is ResolutionState.UNRESOLVED for edge in uses)


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
