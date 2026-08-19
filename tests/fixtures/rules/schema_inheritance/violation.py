from app.schemas.user import UserResponse


class UserDetailResponse(UserResponse):
    email: str
