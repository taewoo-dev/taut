from app.clients import payment_client
from app.database import get_async_session


async def run() -> None:
    async with get_async_session():
        await payment_client.get("/status")
