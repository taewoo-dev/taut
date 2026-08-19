import httpx


def build() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=3.0)
