from __future__ import annotations

from taut.analysis.framework.sqlalchemy import SQLAlchemyProvider
from taut.analysis.framework.sqlalchemy_facts import SQLALCHEMY_MODELS
from taut.analysis.providers import apply_fact_providers, apply_fact_providers_incremental
from taut.domain.ids import ModuleId
from tests.utils.builders import analyze, make_source


def snapshot(*sources: tuple[str, str]):
    return analyze(*(make_source(path, text) for path, text in sources))


def test_no_change_reuses_exact_prior_tuples() -> None:
    provider = SQLAlchemyProvider()
    old = snapshot(
        ("app/models.py", "from sqlalchemy.orm import declarative_base\nBase = declarative_base()")
    )
    previous = provider.analyze(old)
    assert provider.analyze_incremental(old, previous, frozenset()) == previous


def test_incremental_does_not_call_full_analyze() -> None:
    class Spy(SQLAlchemyProvider):
        def analyze(self, snapshot):
            raise AssertionError("full analyze called")

    provider = Spy()
    current = snapshot(
        ("app/models.py", "from sqlalchemy.orm import declarative_base\nBase = declarative_base()")
    )
    previous = SQLAlchemyProvider().analyze(current)
    assert provider.analyze_incremental(current, previous, frozenset())


def test_ordinary_edit_matches_full_and_preserves_unaffected_objects() -> None:
    provider = SQLAlchemyProvider()
    old = snapshot(
        ("app/models.py", "from sqlalchemy.orm import declarative_base\nBase = declarative_base()"),
        ("app/use.py", "x = 1"),
    )
    new = snapshot(
        ("app/models.py", "from sqlalchemy.orm import declarative_base\nBase = declarative_base()"),
        ("app/use.py", "x = 2"),
    )
    previous = provider.analyze(old)
    incremental = provider.analyze_incremental(new, previous, frozenset({ModuleId("app.use")}))
    assert incremental == provider.analyze(new)


def test_transitive_base_model_edit_matches_full() -> None:
    provider = SQLAlchemyProvider()
    old = snapshot(
        ("app/base.py", "class Base: pass"),
        ("app/child.py", "from app.base import Base\nclass Child(Base): pass"),
    )
    new = snapshot(
        ("app/base.py", "class Base: pass\nvalue = 1"),
        ("app/child.py", "from app.base import Base\nclass Child(Base): pass"),
    )
    previous = provider.analyze(old)
    assert provider.analyze_incremental(
        new, previous, frozenset({ModuleId("app.base")})
    ) == provider.analyze(new)


def test_add_module_matches_full() -> None:
    provider = SQLAlchemyProvider()
    old = snapshot(("app/a.py", "x = 1"))
    new = snapshot(("app/a.py", "x = 1"), ("app/b.py", "x = 2"))
    assert provider.analyze_incremental(
        new, provider.analyze(old), frozenset({ModuleId("app.b")})
    ) == provider.analyze(new)


def test_remove_module_matches_full() -> None:
    provider = SQLAlchemyProvider()
    old = snapshot(("app/a.py", "x = 1"), ("app/b.py", "x = 2"))
    new = snapshot(("app/a.py", "x = 1"))
    assert provider.analyze_incremental(
        new, provider.analyze(old), frozenset({ModuleId("app.b")})
    ) == provider.analyze(new)


def test_syntax_failure_and_recovery_match_full() -> None:
    provider = SQLAlchemyProvider()
    old = snapshot(("app/a.py", "x = 1"))
    broken = snapshot(("app/a.py", "def broken(:"))
    recovered = snapshot(("app/a.py", "x = 2"))
    prior = provider.analyze(old)
    assert provider.analyze_incremental(
        broken, prior, frozenset({ModuleId("app.a")})
    ) == provider.analyze(broken)
    assert provider.analyze_incremental(
        recovered, provider.analyze(broken), frozenset({ModuleId("app.a")})
    ) == provider.analyze(recovered)


def test_executor_provenance_path_matches_full() -> None:
    provider = SQLAlchemyProvider()
    old = snapshot(("app/a.py", "x = 1"))
    new = snapshot(("app/a.py", "x = 2"))
    previous = apply_fact_providers(old, (provider,))
    result = apply_fact_providers_incremental(
        new, (provider,), previous, frozenset({ModuleId("app.a")})
    )
    assert result == apply_fact_providers(new, (SQLAlchemyProvider(),))
    assert SQLALCHEMY_MODELS in result.capabilities
