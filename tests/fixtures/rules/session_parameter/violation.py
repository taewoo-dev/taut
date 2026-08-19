from sqlalchemy.ext.asyncio import AsyncSession


async def create_order(session: AsyncSession) -> None:
    await session.commit()
