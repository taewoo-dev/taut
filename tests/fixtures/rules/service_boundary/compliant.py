from app.models import Order


async def create(session: object) -> None:
    await Order.create_one(session)
    await session.commit()
