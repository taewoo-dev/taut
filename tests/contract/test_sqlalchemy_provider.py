from typing import cast

from tests.utils.builders import analyze, make_source

from taut.analysis.framework.sqlalchemy import (
    SQLALCHEMY_MAPPED_COLUMNS,
    SQLALCHEMY_MODELS,
    SQLALCHEMY_QUERIES,
    SQLALCHEMY_RAW_SQL,
    SQLALCHEMY_RELATIONSHIPS,
    SQLALCHEMY_SESSIONS,
    SQLALCHEMY_TRANSACTIONS,
    SQLAlchemyMappedColumnFact,
    SQLAlchemyModelFact,
    SQLAlchemyProvider,
    SQLAlchemyQueryFact,
    SQLAlchemyRawSQLFact,
    SQLAlchemyRelationshipFact,
    SQLAlchemySessionFact,
    SQLAlchemyTransactionFact,
)
from taut.analysis.providers import apply_fact_providers


def test_sqlalchemy_unrelated_module_does_not_leak_models() -> None:
    snapshot = analyze(
        make_source(
            "app/model.py",
            "from sqlalchemy.orm import DeclarativeBase\nclass Base(DeclarativeBase): pass",
        ),
        make_source("other/noise.py", "class Base: pass"),
    )
    result = apply_fact_providers(snapshot, (SQLAlchemyProvider(),))
    models = cast(tuple[SQLAlchemyModelFact, ...], result.capabilities[SQLALCHEMY_MODELS])
    assert all(item.module_id.value == "app.model" for item in models)


def test_sqlalchemy_transaction_query_and_raw_sql_facts() -> None:
    snapshot = analyze(
        make_source(
            "app/db.py",
            "from sqlalchemy import text\ndef run(session):\n    with session.begin():\n        session.execute(text('select 1'))",  # noqa: E501
        )
    )
    result = apply_fact_providers(snapshot, (SQLAlchemyProvider(),))
    assert result.capabilities[SQLALCHEMY_TRANSACTIONS] is not None
    assert result.capabilities[SQLALCHEMY_QUERIES] is not None
    assert result.capabilities[SQLALCHEMY_RAW_SQL] is not None


from taut.domain.facts import ResolutionState  # noqa: E402
from taut.plugins.v1 import SQLAlchemyProvider as PublicSQLAlchemyProvider  # noqa: E402


def test_sqlalchemy_provider_extracts_14_and_20_declarative_and_runtime_facts() -> None:
    snapshot = analyze(
        make_source(
            "app/models.py",
            """from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
class Base(DeclarativeBase): pass
class User(Base):
    id: Mapped[int] = mapped_column(primary_key=True)
    posts: Mapped[list['Post']] = relationship(back_populates='author', lazy='selectin')
""",
        ),
        make_source(
            "app/db.py",
            """from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
async def read(session: AsyncSession):
    await session.execute(select(User))
    await session.execute(text('select 1'))
    await session.commit()
""",
        ),
    )
    result = apply_fact_providers(snapshot, (SQLAlchemyProvider(),))
    models = cast(tuple[SQLAlchemyModelFact, ...], result.capabilities[SQLALCHEMY_MODELS])
    columns = cast(
        tuple[SQLAlchemyMappedColumnFact, ...], result.capabilities[SQLALCHEMY_MAPPED_COLUMNS]
    )
    assert {item.symbol.value for item in models} == {"app.models.Base", "app.models.User"}
    assert len(columns) == 1
    assert columns[0].field.owner_symbol == models[-1].symbol
    assert columns[0].ref.provenance.provider == columns[0].provenance.provider
    assert columns[0].ref.provenance.source_hash == columns[0].provenance.source_hash
    assert result.capabilities[SQLALCHEMY_RELATIONSHIPS]
    assert result.capabilities[SQLALCHEMY_SESSIONS] == ()
    queries = cast(tuple[SQLAlchemyQueryFact, ...], result.capabilities[SQLALCHEMY_QUERIES])
    raw_sql = cast(tuple[SQLAlchemyRawSQLFact, ...], result.capabilities[SQLALCHEMY_RAW_SQL])
    transactions = cast(
        tuple[SQLAlchemyTransactionFact, ...], result.capabilities[SQLALCHEMY_TRANSACTIONS]
    )
    assert {item.operation for item in queries} == {
        "select",
        "execute",
    }
    assert len(raw_sql) == 1
    assert {item.operation for item in transactions} == {"commit"}


def test_sqlalchemy_provider_does_not_leak_nested_or_unresolved_calls() -> None:
    snapshot = analyze(
        make_source(
            "app/models.py",
            """from sqlalchemy.orm import DeclarativeBase, mapped_column
class Base(DeclarativeBase): pass
class User(Base):
    id = mapped_column(String(80))
    value = unknown(mapped_column())
""",
        ),
        make_source(
            "app/other.py",
            """def mapped_column(): return None
def unrelated(): return mapped_column()
""",
        ),
    )
    result = apply_fact_providers(snapshot, (SQLAlchemyProvider(),))
    columns = cast(
        tuple[SQLAlchemyMappedColumnFact, ...], result.capabilities[SQLALCHEMY_MAPPED_COLUMNS]
    )
    assert len(columns) == 1
    assert columns[0].field.name == "id"


def test_nested_declarative_and_factory_wrappers_are_not_sqlalchemy_origins() -> None:
    snapshot = analyze(
        make_source(
            "app/db.py",
            """from sqlalchemy import text
from sqlalchemy.orm import declarative_base, sessionmaker
def wrap(value): return value
Base = declarative_base()
Bad = wrap(declarative_base())
SessionLocal = sessionmaker()
BadFactory = wrap(sessionmaker())
good = SessionLocal()
bad = BadFactory()
""",
        )
    )
    result = apply_fact_providers(snapshot, (SQLAlchemyProvider(),))
    sessions = cast(tuple[SQLAlchemySessionFact, ...], result.capabilities[SQLALCHEMY_SESSIONS])
    assert len(sessions) == 2
    produced = [item for item in sessions if getattr(item, "factory_symbol", None) is not None]
    assert len(produced) == 1
    factory_symbol = produced[0].factory_symbol
    assert factory_symbol is not None
    assert factory_symbol.value == "app.db.SessionLocal"


def test_sqlalchemy_provider_is_public_plugin_contract() -> None:
    provider = PublicSQLAlchemyProvider()
    assert provider.id == "taut.sqlalchemy"
    assert provider.version == "1"
    assert {spec.id for spec in provider.provides} == {
        SQLALCHEMY_MODELS,
        SQLALCHEMY_MAPPED_COLUMNS,
        SQLALCHEMY_RELATIONSHIPS,
        SQLALCHEMY_SESSIONS,
        SQLALCHEMY_TRANSACTIONS,
        SQLALCHEMY_QUERIES,
        SQLALCHEMY_RAW_SQL,
    }


def test_cross_module_legacy_base_fixpoint_is_source_order_independent() -> None:
    snapshot = analyze(
        make_source(
            "app/models.py",
            """from app.base import Base
from sqlalchemy.orm import Mapped
class User(Base):
    id: Mapped[int]
""",
        ),
        make_source(
            "app/base.py",
            """from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()
""",
        ),
    )
    result = apply_fact_providers(snapshot, (SQLAlchemyProvider(),))
    models = cast(tuple[SQLAlchemyModelFact, ...], result.capabilities[SQLALCHEMY_MODELS])
    columns = cast(
        tuple[SQLAlchemyMappedColumnFact, ...], result.capabilities[SQLALCHEMY_MAPPED_COLUMNS]
    )
    assert [model.symbol.value for model in models] == ["app.models.User"]
    assert len(columns) == 1
    assert columns[0].call is None


def test_annotation_only_mapped_and_legacy_column_relationship_are_distinct_facts() -> None:
    snapshot = analyze(
        make_source(
            "app/models.py",
            """from sqlalchemy import Column, Integer
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
class Base(DeclarativeBase): pass
class Modern(Base):
    id: Mapped[int]
    name: Mapped[str] = mapped_column()
    children: Mapped[list['Legacy']] = relationship(lazy='selectin')
class Legacy(Base):
    id = Column(Integer, primary_key=True)
    parent = relationship('Modern', lazy='joined')
""",
        )
    )
    result = apply_fact_providers(snapshot, (SQLAlchemyProvider(),))
    columns = cast(
        tuple[SQLAlchemyMappedColumnFact, ...], result.capabilities[SQLALCHEMY_MAPPED_COLUMNS]
    )
    relationships = cast(
        tuple[SQLAlchemyRelationshipFact, ...], result.capabilities[SQLALCHEMY_RELATIONSHIPS]
    )
    assert {item.name for item in columns} == {"id", "name"}
    assert {item.name for item in relationships} == {"children", "parent"}
    assert next(item for item in columns if item.name == "id").call is None


def test_raw_sql_preserves_expression_metadata_and_resolution_states() -> None:
    snapshot = analyze(
        make_source(
            "app/db.py",
            """from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
async def run(session: AsyncSession, sql: str):
    await session.execute('select 1')
    await session.execute(sql)
    await session.exec_driver_sql('select 2')
    await session.execute(text(f'select {sql}'))
""",
        )
    )
    result = apply_fact_providers(snapshot, (SQLAlchemyProvider(),))
    raw = cast(tuple[SQLAlchemyRawSQLFact, ...], result.capabilities[SQLALCHEMY_RAW_SQL])
    by_operation = {item.operation: item for item in raw if item.operation != "execute"}
    executes = [item for item in raw if item.operation == "execute"]
    assert by_operation["text"].is_dynamic is True
    assert by_operation["text"].argument is not None
    assert by_operation["exec_driver_sql"].is_literal is True
    assert len(executes) == 2
    assert {item.is_literal for item in executes} == {True, False}


def test_ambiguous_conditional_and_unresolved_refs_are_preserved_without_guesses() -> None:
    snapshot = analyze(
        make_source(
            "app/ambiguous.py",
            """from sqlalchemy.orm import DeclarativeBase
if flag:
    from sqlalchemy.orm import mapped_column as mc
else:
    from sqlalchemy import mapped_column as mc
class Base(DeclarativeBase): pass
class User(Base):
    value = mc()
    unknown = Unknown()
""",
        ),
    )
    result = apply_fact_providers(snapshot, (SQLAlchemyProvider(),))
    columns = cast(
        tuple[SQLAlchemyMappedColumnFact, ...], result.capabilities[SQLALCHEMY_MAPPED_COLUMNS]
    )
    assert len(columns) == 1
    assert columns[0].confidence is columns[0].ref.state is ResolutionState.AMBIGUOUS
    assert len(columns[0].ref.candidates) == 2
    assert all(item.name != "unknown" for item in columns)
