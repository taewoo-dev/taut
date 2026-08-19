from app.config import REQUEST_CONFIG
from pydantic import BaseModel


class CreateRequest(BaseModel):
    model_config = REQUEST_CONFIG
