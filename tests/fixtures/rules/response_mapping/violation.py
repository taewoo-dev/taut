from app.schemas.user import UserResponse


def route(data):
    return UserResponse(**data)
