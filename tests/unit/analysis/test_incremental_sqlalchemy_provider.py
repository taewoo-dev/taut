from __future__ import annotations

from typing import cast

from tests.utils.builders import analyze, make_source

from taut.analysis.framework.sqlalchemy import SQLAlchemyProvider
from taut.analysis.framework.sqlalchemy_facts import (
    SQLALCHEMY_MAPPED_COLUMNS,
    SQLALCHEMY_MODELS,
    SQLALCHEMY_QUERIES,
    SQLALCHEMY_RAW_SQL,
    SQLALCHEMY_TRANSACTIONS,
    SQLAlchemyMappedColumnFact,
    SQLAlchemyModelFact,
    SQLAlchemyTransactionFact,
)
from taut.analysis.providers import apply_fact_providers, apply_fact_providers_incremental
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId
from taut.domain.snapshot import AnalysisSnapshot


def snapshot(*sources: tuple[str, str]) -> AnalysisSnapshot:
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
        def analyze(self, snapshot: AnalysisSnapshot) -> FrozenMap[str, tuple[object, ...]]:
            del snapshot
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


def test_changed_child_uses_unchanged_custom_model_parent_and_preserves_other_model() -> None:
    provider = SQLAlchemyProvider()
    base = "from sqlalchemy.orm import DeclarativeBase\nclass Base(DeclarativeBase): pass"
    child = (
        "from app.base import Base\n"
        "from sqlalchemy.orm import Mapped, mapped_column\n"
        "class User(Base):\n"
        "    id: Mapped[int] = mapped_column()\n"
    )
    other = "from sqlalchemy.orm import DeclarativeBase\nclass Other(DeclarativeBase): pass"
    old = snapshot(("app/base.py", base), ("app/child.py", child), ("app/other.py", other))
    new = snapshot(
        ("app/base.py", base),
        ("app/child.py", child + "    name: Mapped[str]\n"),
        ("app/other.py", other),
    )
    previous = provider.analyze(old)
    incremental = provider.analyze_incremental(new, previous, frozenset({ModuleId("app.child")}))
    assert incremental == provider.analyze(new)
    models = cast(tuple[SQLAlchemyModelFact, ...], incremental[SQLALCHEMY_MODELS])
    old_models = cast(tuple[SQLAlchemyModelFact, ...], previous[SQLALCHEMY_MODELS])
    assert {item.symbol.value for item in models} == {
        "app.base.Base",
        "app.child.User",
        "app.other.Other",
    }
    assert next(item for item in models if item.module_id == ModuleId("app.other")) is next(
        item for item in old_models if item.module_id == ModuleId("app.other")
    )
    columns = cast(tuple[SQLAlchemyMappedColumnFact, ...], incremental[SQLALCHEMY_MAPPED_COLUMNS])
    assert {item.name for item in columns} == {"id", "name"}


def test_changed_declarative_base_and_transitive_child_match_full() -> None:
    provider = SQLAlchemyProvider()
    old = snapshot(
        (
            "app/base.py",
            "from sqlalchemy.orm import DeclarativeBase\nclass Base(DeclarativeBase): pass",
        ),
        (
            "app/child.py",
            "from app.base import Base\nclass User(Base): pass",
        ),
    )
    new = snapshot(
        (
            "app/base.py",
            "from sqlalchemy.orm import DeclarativeBase\nclass Base(DeclarativeBase):\n    x = 1",
        ),
        (
            "app/child.py",
            "from app.base import Base\nclass User(Base): pass",
        ),
    )
    impacted = frozenset({ModuleId("app.base"), ModuleId("app.child")})
    incremental = provider.analyze_incremental(new, provider.analyze(old), impacted)
    assert incremental == provider.analyze(new)
    models = cast(tuple[SQLAlchemyModelFact, ...], incremental[SQLALCHEMY_MODELS])
    assert {item.symbol.value for item in models} == {
        "app.base.Base",
        "app.child.User",
    }


def test_runtime_fact_edit_preserves_all_capability_ordering() -> None:
    provider = SQLAlchemyProvider()
    before = (
        "from sqlalchemy import select, text\n"
        "from sqlalchemy.ext.asyncio import AsyncSession\n"
        "async def run(session: AsyncSession):\n"
        "    await session.execute(select(User))\n"
        "    await session.execute(text('select 1'))\n"
        "    await session.commit()\n"
    )
    after = before.replace("select 1", "select 2") + "    await session.rollback()\n"
    old = snapshot(("app/db.py", before), ("app/noise.py", "value = 1"))
    new = snapshot(("app/db.py", after), ("app/noise.py", "value = 1"))
    incremental = provider.analyze_incremental(
        new, provider.analyze(old), frozenset({ModuleId("app.db")})
    )
    assert incremental == provider.analyze(new)
    assert len(incremental[SQLALCHEMY_QUERIES]) == 3
    assert len(incremental[SQLALCHEMY_RAW_SQL]) == 1
    transactions = cast(tuple[SQLAlchemyTransactionFact, ...], incremental[SQLALCHEMY_TRANSACTIONS])
    assert {item.operation for item in transactions} == {
        "commit",
        "rollback",
    }
