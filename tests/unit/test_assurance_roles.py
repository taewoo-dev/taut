from tests.utils.builders import analyze, make_context, make_source

from taut.analysis.providers import apply_fact_providers
from taut.assurance_roles import semantic_role_issues
from taut.loading.default_configuration import default_project_configuration
from taut.policy.packs import builtin_backend_providers


def test_semantic_role_assurance_ignores_non_production_routes() -> None:
    snapshot = analyze(
        make_source(
            "tests/test_routes.py",
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.get('/probe')\n"
            "async def probe(): return {'ok': True}",
        )
    )
    snapshot = apply_fact_providers(snapshot, builtin_backend_providers())
    context = make_context(
        snapshot,
        roles={"test": ("tests/**",)},
        zones={"test": ("tests/**",)},
    )

    issues = semantic_role_issues(
        snapshot,
        context.classification,
        default_project_configuration().policy.code,
    )

    assert issues == ()


def test_semantic_role_assurance_rejects_production_route_outside_router_role() -> None:
    snapshot = analyze(
        make_source(
            "app/main.py",
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.get('/probe')\n"
            "async def probe(): return {'ok': True}",
        )
    )
    snapshot = apply_fact_providers(snapshot, builtin_backend_providers())
    context = make_context(
        snapshot,
        roles={"bootstrap": ("app/**",)},
    )

    issues = semantic_role_issues(
        snapshot,
        context.classification,
        default_project_configuration().policy.code,
    )

    assert [issue.code for issue in issues] == ["ROLE_SEMANTIC_MISMATCH"]
