from sqlalchemy import select


async def fetch_rows(session: object) -> tuple[object, ...]:
    rows = await session.execute(select(object))
    return tuple(rows)
