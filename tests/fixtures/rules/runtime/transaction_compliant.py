from app.clients import payment_client


async def run() -> None:
    await payment_client.get("/status")
