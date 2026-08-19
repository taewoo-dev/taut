import httpx


async def test_list(client: httpx.AsyncClient) -> None:
    await client.get("/orders")
