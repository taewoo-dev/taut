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
    SQLAlchemyTransactionFact,
)
from taut.analysis.providers import apply_fact_providers


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
