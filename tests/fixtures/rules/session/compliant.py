from app.database import get_async_session


async def run_service() -> None:
    async with get_async_session():
        pass
