"""First-party framework fact providers."""

from .fastapi import (
    FASTAPI_DEPENDENCIES,
    FASTAPI_ENDPOINTS,
    FASTAPI_PROVIDER_ID,
    FASTAPI_RESPONSE_MODELS,
    FASTAPI_ROUTERS,
    FastAPIConfidence,
    FastAPIDependencyFact,
    FastAPIEndpointFact,
    FastAPIProvider,
    FastAPIResponseModelFact,
    FastAPIRouterFact,
)

__all__ = [
    "FASTAPI_DEPENDENCIES",
    "FASTAPI_ENDPOINTS",
    "FASTAPI_PROVIDER_ID",
    "FASTAPI_RESPONSE_MODELS",
    "FASTAPI_ROUTERS",
    "FastAPIConfidence",
    "FastAPIDependencyFact",
    "FastAPIEndpointFact",
    "FastAPIProvider",
    "FastAPIResponseModelFact",
    "FastAPIRouterFact",
]
