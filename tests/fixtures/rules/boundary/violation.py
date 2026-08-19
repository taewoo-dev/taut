from app.models.job import Job
from sqlalchemy import select


def task_entrypoint() -> object:
    return select(Job)
