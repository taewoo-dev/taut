from pydantic import BaseModel


class ReportSnapshot(BaseModel):
    title: str
