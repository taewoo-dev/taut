from app.database import get_async_session


async def run() -> None:
    async with get_async_session(), get_async_session():
        pass
