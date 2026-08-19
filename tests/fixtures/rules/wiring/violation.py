import httpx


def run() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=3.0)
