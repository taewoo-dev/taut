from fastapi import HTTPException
from sqlalchemy import select


async def create(session: object) -> None:
    await session.execute(select(object))
    raise HTTPException(status_code=409)
