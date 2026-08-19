from tests.client import WatchTestClient


async def test_list(client: WatchTestClient) -> None:
    await client.list_orders()
