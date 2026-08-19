from pydantic import BaseModel


class ReportSnapshotV1(BaseModel):
    title: str
