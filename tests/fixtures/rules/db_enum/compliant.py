from app.enums import Status
from sqlalchemy import Enum as SQLEnum

status = SQLEnum(
    Status,
    name="status",
    values_callable=lambda enum: [item.value for item in enum],
    native_enum=True,
)
