from app.services import create_order


async def create(request: object) -> object:
    return await create_order(request)
