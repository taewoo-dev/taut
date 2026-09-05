from __future__ import annotations

from taut.analysis.framework.fastapi import FASTAPI_ENDPOINTS
from taut.analysis.framework.sqlalchemy import SQLALCHEMY_MODELS
from taut.analysis.framework.tortoise import TORTOISE_MODELS
from taut.configuration.code_conventions import CodeConventionPolicy
from taut.configuration.manifest import ClassificationIndex, ProjectManifest, Zone
from taut.domain.assurance import AssuranceIssue
from taut.domain.ids import ModuleId
from taut.domain.snapshot import AnalysisSnapshot


def semantic_role_issues(
    snapshot: AnalysisSnapshot,
    classifications: ClassificationIndex,
    code: CodeConventionPolicy,
    manifest: ProjectManifest | None = None,
) -> tuple[AssuranceIssue, ...]:
    contracts = (
        (FASTAPI_ENDPOINTS, code.router_roles, "FastAPI endpoint", "router"),
        (SQLALCHEMY_MODELS, code.model_roles, "SQLAlchemy model", "model"),
        (TORTOISE_MODELS, code.model_roles, "Tortoise model", "model"),
    )
    issues: list[AssuranceIssue] = []
    for capability, expected_roles, label, expected in contracts:
        for fact in snapshot.capabilities.get(capability, ()):
            module_id = getattr(fact, "module_id", None)
            if not isinstance(module_id, ModuleId) or module_id not in classifications.modules:
                continue
            classification = classifications.modules[module_id]
            if classification.zone != Zone("prod") or classification.role in expected_roles:
                continue
            path = snapshot.modules[module_id].module.path.value
            issues.append(
                AssuranceIssue(
                    "ROLE_SEMANTIC_MISMATCH",
                    f"{label}의 architecture role이 semantic evidence와 맞지 않습니다.",
                    path,
                    f"{expected} 역할의 위치로 구현을 옮기거나 혼합된 책임을 분리하세요. "
                    "현재 코드를 통과시키기 위해 역할이나 허용 범위를 넓히지 마세요. "
                    + (manifest.placement_hint(expected_roles) if manifest is not None else ""),
                )
            )
    return tuple(issues)
