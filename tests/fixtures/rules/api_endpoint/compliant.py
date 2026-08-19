from app.api import ERRORS, UserResponse
from fastapi import APIRouter

router = APIRouter()


@router.get("/users", response_model=UserResponse, responses=ERRORS)
async def get_user() -> UserResponse:
    """Return one user."""
