from sqlalchemy import update


async def update_rows(session: object) -> None:
    await session.execute(update(object))
    await session.commit()
