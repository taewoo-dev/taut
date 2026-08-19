from pydantic import BaseModel, ConfigDict


class CreateRequest(BaseModel):
    model_config = ConfigDict(frozen=True)
