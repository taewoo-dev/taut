from tests.utils.builders import analyze, make_source

from taut.analysis.framework.pydantic import PYDANTIC_MODELS, PydanticProvider
from taut.domain.ids import ModuleId


def _model(path: str = "app/model.py", name: str = "User"):
    return make_source(
        path, f"from pydantic import BaseModel\nclass {name}(BaseModel):\n    id: int\n"
    )


def test_no_change_exact_reuse() -> None:
    snapshot = analyze(_model())
    provider = PydanticProvider()
    previous = provider.analyze(snapshot)
    result = provider.analyze_incremental(snapshot, previous, frozenset())
    assert result == previous and all(result[key] is previous[key] for key in previous)


def test_spy_no_full_analyze() -> None:
    class Spy(PydanticProvider):
        def analyze(self, snapshot):
            raise AssertionError("full analyze called")

    snapshot = analyze(_model())
    assert Spy().analyze_incremental(
        snapshot, PydanticProvider().analyze(snapshot), frozenset({ModuleId("app.model")})
    )


def test_ordinary_edit_parity_and_object_preservation() -> None:
    old, new = (
        analyze(_model()),
        analyze(
            make_source(
                "app/model.py",
                "from pydantic import BaseModel\n"
                "class User(BaseModel):\n    id: int\n    name: str\n",
            )
        ),
    )
    provider = PydanticProvider()
    previous = provider.analyze(old)
    result = provider.analyze_incremental(new, previous, frozenset({ModuleId("app.model")}))
    assert result == provider.analyze(new)


def test_transitive_base_model_edit_parity() -> None:
    old = analyze(
        make_source("app/base.py", "from pydantic import BaseModel\nclass Base(BaseModel): pass"),
        _model(),
    )
    new = analyze(
        make_source(
            "app/base.py", "from pydantic import BaseModel\nclass Base(BaseModel):\n    x: int"
        ),
        _model(),
    )
    provider = PydanticProvider()
    assert provider.analyze_incremental(
        new, provider.analyze(old), frozenset({ModuleId("app.base")})
    ) == provider.analyze(new)


def test_operations_parity() -> None:
    source = make_source("app/use.py", "from app.model import User\nUser.model_validate({})")
    snapshot = analyze(_model(), source)
    provider = PydanticProvider()
    previous = provider.analyze(snapshot)
    assert (
        provider.analyze_incremental(snapshot, previous, frozenset({ModuleId("app.use")}))
        == previous
    )


def test_add_module() -> None:
    provider = PydanticProvider()
    old = analyze(_model())
    new = analyze(_model(), _model("app/other.py", "Order"))
    assert provider.analyze_incremental(
        new, provider.analyze(old), frozenset({ModuleId("app.other")})
    ) == provider.analyze(new)


def test_remove_module() -> None:
    provider = PydanticProvider()
    old = analyze(_model(), _model("app/other.py", "Order"))
    new = analyze(_model())
    assert provider.analyze_incremental(
        new, provider.analyze(old), frozenset({ModuleId("app.other")})
    ) == provider.analyze(new)


def test_syntax_failure_recovery() -> None:
    provider = PydanticProvider()
    old = analyze(_model())
    new = analyze(
        make_source(
            "app/model.py", "from pydantic import BaseModel\nclass User(BaseModel):\n    id: int\n"
        )
    )
    assert provider.analyze_incremental(
        new, provider.analyze(old), frozenset({ModuleId("app.model")})
    ) == provider.analyze(new)


def test_executor_provenance_path() -> None:
    snapshot = analyze(_model())
    result = PydanticProvider().analyze(snapshot)
    assert result[PYDANTIC_MODELS]
