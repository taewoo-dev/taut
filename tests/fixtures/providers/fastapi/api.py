from fastapi import Depends
from tests.fixtures.providers.fastapi.models import UserResponse
from tests.fixtures.providers.fastapi.routes import router as api_router


def get_user() -> UserResponse:
    return UserResponse(name="Ada")


@api_router.get("/users", response_model=UserResponse)
def users(limit: int = Depends(get_user)) -> UserResponse:
    return get_user()
