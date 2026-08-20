from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, sessionmaker


def sync_read(session: Session):
    statement = select("User")
    return session.execute(statement).scalars()


async def async_write(session: AsyncSession):
    async with session.begin():
        await session.execute(text("select 1"))
        await session.commit()
        await session.rollback()


factory = sessionmaker()
