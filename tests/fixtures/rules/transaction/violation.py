from sqlalchemy.ext.asyncio import AsyncSession


async def query(session: AsyncSession):
    await session.rollback()
