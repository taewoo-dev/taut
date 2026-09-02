from tests.utils.builders import analyze, make_source

from taut.analysis.framework.fastapi import FASTAPI_ENDPOINTS
from taut.analysis.framework.pydantic import PYDANTIC_MODELS
from taut.analysis.framework.sqlalchemy import SQLALCHEMY_MODELS
from taut.analysis.framework.tortoise import TORTOISE_MODELS
from taut.analysis.providers import apply_fact_providers
from taut.domain.frozen import FrozenMap
from taut.domain.snapshot import AnalysisSnapshot
from taut.plugins.v1 import (
    BUILTIN_BACKEND_PROVIDER_IDS,
    builtin_backend_providers,
)
from taut.plugins.v1 import (
    FASTAPI_ENDPOINTS as PUBLIC_FASTAPI_ENDPOINTS,
)
from taut.plugins.v1 import (
    PYDANTIC_MODELS as PUBLIC_PYDANTIC_MODELS,
)
from taut.plugins.v1 import (
    SQLALCHEMY_MODELS as PUBLIC_SQLALCHEMY_MODELS,
)
from taut.plugins.v1 import TORTOISE_MODELS as PUBLIC_TORTOISE_MODELS
from taut.policy.packs import load_fact_provider


def test_builtin_backend_bundle_combines_framework_capabilities_deterministically() -> None:
    snapshot = analyze(
        make_source(
            "app/models.py",
            """from pydantic import BaseModel
from sqlalchemy.orm import DeclarativeBase
from tortoise.models import Model
class Schema(BaseModel): value: int
class Base(DeclarativeBase): pass
class Entity(Base): value = 1
class TortoiseEntity(Model): pass
""",
        ),
        make_source(
            "app/api.py",
            """from fastapi import APIRouter
router = APIRouter()
@router.get('/items')
def items(): pass
""",
        ),
    )
    result = apply_fact_providers(snapshot, builtin_backend_providers())
    assert result.capabilities[FASTAPI_ENDPOINTS]
    assert result.capabilities[SQLALCHEMY_MODELS]
    assert result.capabilities[PYDANTIC_MODELS]
    assert result.capabilities[TORTOISE_MODELS]
    assert result.coverage.unavailable_capabilities == ()
    assert {item.provider for item in result.capability_provenance.values()} >= {
        "taut.fastapi",
        "taut.sqlalchemy",
        "taut.pydantic",
        "taut.tortoise",
    }


def test_builtin_provider_ids_and_public_capabilities_are_compatible() -> None:
    assert BUILTIN_BACKEND_PROVIDER_IDS == (
        "taut.python-core",
        "taut.fastapi",
        "taut.pydantic",
        "taut.sqlalchemy",
        "taut.tortoise",
    )
    assert PUBLIC_FASTAPI_ENDPOINTS == FASTAPI_ENDPOINTS
    assert PUBLIC_SQLALCHEMY_MODELS == SQLALCHEMY_MODELS
    assert PUBLIC_PYDANTIC_MODELS == PYDANTIC_MODELS
    assert PUBLIC_TORTOISE_MODELS == TORTOISE_MODELS
    assert [load_fact_provider(item).id for item in BUILTIN_BACKEND_PROVIDER_IDS] == list(
        BUILTIN_BACKEND_PROVIDER_IDS
    )


def test_provider_failure_is_isolated_from_other_framework_capabilities() -> None:
    snapshot = analyze(make_source("app/models.py", "class Plain: pass"))
    providers = builtin_backend_providers()

    class Broken:
        id = "test.broken"
        version = "1"
        provides = providers[1].provides

        def analyze(self, snapshot: AnalysisSnapshot) -> FrozenMap[str, tuple[object, ...]]:
            raise RuntimeError("broken framework")

    result = apply_fact_providers(snapshot, (providers[0], Broken(), providers[2]))
    assert result.capabilities[PYDANTIC_MODELS] == ()
    assert result.coverage.unavailable_capabilities
    assert result.capability_provenance.get("taut.pydantic.models@1") is not None
