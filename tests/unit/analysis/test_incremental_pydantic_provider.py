from __future__ import annotations

from typing import cast

from tests.utils.builders import analyze, make_source

from taut.analysis.contracts import SourceInput
from taut.analysis.framework.pydantic import (
    PYDANTIC_CONFIGS,
    PYDANTIC_FIELDS,
    PYDANTIC_MODELS,
    PYDANTIC_OPERATIONS,
    PYDANTIC_SERIALIZERS,
    PYDANTIC_VALIDATORS,
    PydanticFieldFact,
    PydanticModelFact,
    PydanticOperationFact,
    PydanticProvider,
)
from taut.analysis.providers import apply_fact_providers, apply_fact_providers_incremental
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId
from taut.domain.snapshot import AnalysisSnapshot


def _model(path: str = "app/model.py", name: str = "User") -> SourceInput:
    return make_source(
        path,
        f"from pydantic import BaseModel\nclass {name}(BaseModel):\n    id: int\n",
    )


def test_no_change_exactly_reuses_every_prior_tuple() -> None:
    snapshot = analyze(_model())
    provider = PydanticProvider()
    previous = provider.analyze(snapshot)
    result = provider.analyze_incremental(snapshot, previous, frozenset())
    assert result == previous
    assert all(result[key] is previous[key] for key in previous)


def test_incremental_path_never_calls_full_analyze() -> None:
    class Spy(PydanticProvider):
        def analyze(self, snapshot: AnalysisSnapshot) -> FrozenMap[str, tuple[object, ...]]:
            del snapshot
            raise AssertionError("full analyze called")

    snapshot = analyze(_model())
    previous = PydanticProvider().analyze(snapshot)
    result = Spy().analyze_incremental(snapshot, previous, frozenset({ModuleId("app.model")}))
    assert result == previous


def test_ordinary_model_edit_matches_full_and_preserves_unaffected_model() -> None:
    provider = PydanticProvider()
    old = analyze(_model(), _model("app/other.py", "Order"))
    new = analyze(
        make_source(
            "app/model.py",
            "from pydantic import BaseModel\nclass User(BaseModel):\n    id: int\n    name: str\n",
        ),
        _model("app/other.py", "Order"),
    )
    previous = provider.analyze(old)
    incremental = provider.analyze_incremental(new, previous, frozenset({ModuleId("app.model")}))
    assert incremental == provider.analyze(new)
    old_models = cast(tuple[PydanticModelFact, ...], previous[PYDANTIC_MODELS])
    models = cast(tuple[PydanticModelFact, ...], incremental[PYDANTIC_MODELS])
    assert next(item for item in models if item.module_id == ModuleId("app.other")) is next(
        item for item in old_models if item.module_id == ModuleId("app.other")
    )


def test_changed_child_uses_unchanged_custom_model_parent() -> None:
    provider = PydanticProvider()
    base = "from pydantic import BaseModel\nclass Base(BaseModel): pass"
    child = "from app.base import Base\nclass User(Base):\n    id: int\n"
    old = analyze(make_source("app/base.py", base), make_source("app/child.py", child))
    new = analyze(
        make_source("app/base.py", base),
        make_source("app/child.py", child + "    name: str\n"),
    )
    incremental = provider.analyze_incremental(
        new, provider.analyze(old), frozenset({ModuleId("app.child")})
    )
    assert incremental == provider.analyze(new)
    models = cast(tuple[PydanticModelFact, ...], incremental[PYDANTIC_MODELS])
    assert {item.symbol.value for item in models} == {
        "app.base.Base",
        "app.child.User",
    }
    fields = cast(tuple[PydanticFieldFact, ...], incremental[PYDANTIC_FIELDS])
    assert {item.name for item in fields} == {"id", "name"}


def test_changed_base_and_transitive_child_match_full() -> None:
    provider = PydanticProvider()
    child = "from app.base import Base\nclass User(Base):\n    value: int"
    old = analyze(
        make_source("app/base.py", "from pydantic import BaseModel\nclass Base(BaseModel): pass"),
        make_source("app/child.py", child),
    )
    new = analyze(
        make_source(
            "app/base.py",
            "from pydantic import BaseModel\nclass Base(BaseModel):\n    base_id: int",
        ),
        make_source("app/child.py", child),
    )
    impacted = frozenset({ModuleId("app.base"), ModuleId("app.child")})
    assert provider.analyze_incremental(new, provider.analyze(old), impacted) == provider.analyze(
        new
    )


def test_operation_consumer_edit_uses_global_model_symbols() -> None:
    provider = PydanticProvider()
    old = analyze(
        _model(),
        make_source("app/use.py", "from app.model import User\nUser.model_validate({})"),
    )
    new = analyze(
        _model(),
        make_source(
            "app/use.py",
            "from app.model import User\nUser.model_validate({})\nUser.model_construct(id=1)",
        ),
    )
    incremental = provider.analyze_incremental(
        new, provider.analyze(old), frozenset({ModuleId("app.use")})
    )
    assert incremental == provider.analyze(new)
    operations = cast(tuple[PydanticOperationFact, ...], incremental[PYDANTIC_OPERATIONS])
    assert {item.operation for item in operations} == {
        "model_validate",
        "model_construct",
    }


def test_validator_serializer_and_config_edit_matches_full() -> None:
    provider = PydanticProvider()
    before = """from pydantic import BaseModel, field_validator
class User(BaseModel):
    value: int
    @field_validator('value')
    @classmethod
    def valid(cls, value): return value
"""
    after = (
        before.replace(
            "from pydantic import BaseModel, field_validator",
            "from pydantic import BaseModel, ConfigDict, field_serializer, field_validator",
        )
        + """    model_config = ConfigDict(extra='forbid')
    @field_serializer('value')
    def serial(self, value): return value
"""
    )
    old = analyze(make_source("app/model.py", before))
    new = analyze(make_source("app/model.py", after))
    incremental = provider.analyze_incremental(
        new, provider.analyze(old), frozenset({ModuleId("app.model")})
    )
    assert incremental == provider.analyze(new)
    assert incremental[PYDANTIC_VALIDATORS]
    assert incremental[PYDANTIC_SERIALIZERS]
    assert incremental[PYDANTIC_CONFIGS]


def test_add_and_remove_real_model_modules_match_full() -> None:
    provider = PydanticProvider()
    one = analyze(_model())
    two = analyze(_model(), _model("app/other.py", "Order"))
    added = provider.analyze_incremental(
        two, provider.analyze(one), frozenset({ModuleId("app.other")})
    )
    removed = provider.analyze_incremental(one, added, frozenset({ModuleId("app.other")}))
    assert added == provider.analyze(two)
    assert removed == provider.analyze(one)


def test_syntax_failure_then_recovery_matches_fresh_each_time() -> None:
    provider = PydanticProvider()
    old = analyze(_model())
    broken = analyze(make_source("app/model.py", "class User("))
    recovered = analyze(
        make_source(
            "app/model.py",
            "from pydantic import BaseModel\nclass User(BaseModel):\n    name: str",
        )
    )
    impacted = frozenset({ModuleId("app.model")})
    broken_incremental = provider.analyze_incremental(broken, provider.analyze(old), impacted)
    recovered_incremental = provider.analyze_incremental(recovered, broken_incremental, impacted)
    assert broken_incremental == provider.analyze(broken)
    assert recovered_incremental == provider.analyze(recovered)


def test_executor_provenance_path_matches_full_snapshot() -> None:
    provider = PydanticProvider()
    old = analyze(_model())
    new = analyze(
        make_source(
            "app/model.py",
            "from pydantic import BaseModel\nclass User(BaseModel):\n    id: int\n    x: int",
        )
    )
    previous = apply_fact_providers(old, (provider,))
    incremental = apply_fact_providers_incremental(
        new, (provider,), previous, frozenset({ModuleId("app.model")})
    )
    assert incremental == apply_fact_providers(new, (PydanticProvider(),))
