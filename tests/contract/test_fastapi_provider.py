from typing import cast

from tests.utils.builders import analyze, make_source

from taut.analysis.framework.fastapi import (
    FASTAPI_DEPENDENCIES,
    FASTAPI_ENDPOINTS,
    FASTAPI_RESPONSE_MODELS,
    FASTAPI_ROUTERS,
    FastAPIConfidence,
    FastAPIDependencyFact,
    FastAPIEndpointFact,
    FastAPIProvider,
    FastAPIResponseModelFact,
)
from taut.analysis.providers import apply_fact_providers


def test_fastapi_provider_extracts_alias_reexported_router_and_typed_contracts() -> None:
    snapshot = analyze(
        make_source("app/routes.py", "from fastapi import APIRouter as Router\nrouter = Router()"),
        make_source(
            "app/api.py",
            """from fastapi import Depends
from app.routes import router as api_router
from app.models import UserResponse

def load_user():
    return UserResponse()

@api_router.get('/users', response_model=UserResponse)
def users(limit: int = Depends(load_user)):
    return load_user()
""",
        ),
        make_source(
            "app/models.py",
            "from pydantic import BaseModel as Schema\nclass UserResponse(Schema):\n    name: str",
        ),
    )
    result = apply_fact_providers(snapshot, (FastAPIProvider(),))

    routers = result.capabilities[FASTAPI_ROUTERS]
    endpoints = cast(tuple[FastAPIEndpointFact, ...], result.capabilities[FASTAPI_ENDPOINTS])
    dependencies = cast(
        tuple[FastAPIDependencyFact, ...], result.capabilities[FASTAPI_DEPENDENCIES]
    )
    models = cast(
        tuple[FastAPIResponseModelFact, ...], result.capabilities[FASTAPI_RESPONSE_MODELS]
    )
    assert len(routers) == 1
    assert len(endpoints) == 1
    assert isinstance(endpoints[0], FastAPIEndpointFact)
    assert endpoints[0].router.value == "app.routes.router"
    assert endpoints[0].path == "'/users'"
    assert endpoints[0].response_model is not None
    assert endpoints[0].confidence is FastAPIConfidence.RESOLVED
    assert len(dependencies) == 1
    assert dependencies[0].parameter == "limit"
    assert dependencies[0].provider is not None
    assert dependencies[0].provider.value == "app.api.load_user"
    assert len(models) == 1


def test_fastapi_provider_preserves_conditional_and_ambiguous_resolution() -> None:
    snapshot = analyze(
        make_source(
            "app/api.py",
            """from fastapi import APIRouter
router = APIRouter()
if enabled:
    route = router
else:
    route = router
@route.get('/')
def index():
    pass
""",
        )
    )
    result = apply_fact_providers(snapshot, (FastAPIProvider(),))
    endpoints = cast(tuple[FastAPIEndpointFact, ...], result.capabilities[FASTAPI_ENDPOINTS])
    assert len(endpoints) == 1
    assert endpoints[0].confidence in {
        FastAPIConfidence.CONDITIONAL,
        FastAPIConfidence.AMBIGUOUS,
        FastAPIConfidence.RESOLVED,
    }
