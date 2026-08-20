from pydantic import BaseModel as Schema


class UserResponse(Schema):
    name: str
