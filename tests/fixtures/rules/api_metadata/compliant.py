from fastapi import APIRouter, Query

router = APIRouter(tags=["orders"])


@router.get("/")
async def list_orders(page: int = Query(1, description="Page number")) -> list[object]:
    return []
