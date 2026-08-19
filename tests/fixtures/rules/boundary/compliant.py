from app.services.jobs import run_job


async def task_entrypoint() -> None:
    await run_job()
