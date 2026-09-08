from fastapi import APIRouter

from app.service import get_greeting

router = APIRouter(prefix="/greetings", tags=["greetings"])


@router.get("/", response_model=str, responses={200: {"description": "Greeting"}})
def greeting() -> str:
    """Return the application's greeting."""
    return get_greeting()
