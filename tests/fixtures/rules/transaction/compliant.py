from sqlalchemy.ext.asyncio import AsyncSession


async def save(session: AsyncSession):
    await session.commit()
