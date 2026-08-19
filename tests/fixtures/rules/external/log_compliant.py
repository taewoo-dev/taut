import httpx
from app.observability import external_call

with external_call(system="payment", operation="get"):
    httpx.get("https://example.test")
