from fastapi import APIRouter, Query

router = APIRouter()


@router.get("/")
async def list_orders(page: int = Query(1)) -> list[object]:
    return []
