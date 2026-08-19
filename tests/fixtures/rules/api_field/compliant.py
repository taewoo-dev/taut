from pydantic import BaseModel, Field


class UserResponse(BaseModel):
    name: str = Field(description="Display name", examples=["Ada"])
