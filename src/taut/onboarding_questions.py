"""Question construction for the versioned onboarding contract."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from taut.configuration.assurance import BUILTIN_ASSURANCE_FEATURES
from taut.onboarding_policy import InitPolicyAnswers, missing_policy_decisions
from taut.onboarding_roles import InitRoleObservation
from taut.onboarding_scope import InitSourceScope
from taut.onboarding_size import InitSizePolicy


@dataclass(frozen=True)
class InitQuestion:
    id: str
    prompt: str
    choices: tuple[str, ...]
    recommended: str
    evidence: tuple[str, ...]


def build_init_questions(
    *,
    paths: tuple[str, ...],
    source_scope: InitSourceScope,
    source_scope_resolved: bool,
    architecture_accepted: bool,
    unresolved_architecture_edges: tuple[tuple[str, str], ...],
    role_observations: tuple[InitRoleObservation, ...],
    role_overrides: dict[str, str],
    feature_answers: dict[str, str],
    expectations: dict[str, str],
    feature_evidence: dict[str, list[str]],
    policy: InitPolicyAnswers,
    observed_response_mappers: tuple[str, ...],
    size: InitSizePolicy,
) -> tuple[InitQuestion, ...]:
    questions: list[InitQuestion] = []
    if not source_scope_resolved:
        questions.append(
            InitQuestion(
                "source_scope.accept_observed",
                "패키징 메타데이터와 Python 경로에서 계산한 source roots를 사용할까요?",
                ("accept", "override"),
                "override" if source_scope.conflicts else "accept",
                source_scope.question_evidence(),
            )
        )
    if not architecture_accepted:
        questions.append(
            InitQuestion(
                "architecture.accept_observed",
                "현재 import 관계가 의도한 정책에 맞는지 검토하세요. "
                "위반은 코드를 먼저 수정하세요.",
                ("accept", "review"),
                "review",
                paths,
            )
        )
    for source, target in unresolved_architecture_edges:
        questions.append(
            InitQuestion(
                f"architecture.edge.{source}->{target}",
                f"위험한 import edge {source} -> {target}를 허용할지 결정하세요.",
                ("allow_with_reason", "deny_with_reason"),
                "deny_with_reason",
                (f"{source}->{target}",),
            )
        )
    if not size.resolved:
        questions.append(
            InitQuestion(
                "size.accept_observed",
                "현재 파일 크기 분포에서 계산한 초기 역할별 상한을 사용할까요?",
                ("accept", "override"),
                "accept",
                size.evidence(),
            )
        )
    low_confidence: dict[str, list[InitRoleObservation]] = {}
    for observation in role_observations:
        if not observation.requires_review or observation.path in role_overrides:
            continue
        if observation.confidence == "low":
            parent = PurePosixPath(observation.path).parent.as_posix()
            low_confidence.setdefault(parent, []).append(observation)
        else:
            questions.append(_role_question(observation))
    for parent, observations in sorted(low_confidence.items()):
        selector = f"{parent}/**/*.py + {parent}/**/*.pyi" if parent != "." else "*.py + *.pyi"
        questions.append(
            InitQuestion(
                f"role_group.{parent}",
                f"{parent} 아래 파일의 역할 근거가 부족합니다. "
                "기존 역할에 맞게 코드를 배치하세요. "
                "새 구조라면 지속 적용할 role_selectors를 검토하세요.",
                ("provide_role_selector", "provide_exact_roles"),
                "provide_role_selector",
                (selector, *(item.path for item in observations)),
            )
        )
    for name in BUILTIN_ASSURANCE_FEATURES:
        if name not in feature_answers:
            questions.append(
                InitQuestion(
                    f"feature.{name}",
                    f"{name} 정책 영역의 기대 상태를 확인하세요.",
                    ("required", "absent"),
                    expectations[name],
                    tuple(feature_evidence[name]),
                )
            )
    for feature, required_values in missing_policy_decisions(expectations, policy):
        questions.append(
            InitQuestion(
                f"policy.{feature}",
                f"{feature} 정책을 활성화할 정확한 값을 입력하세요: {required_values}.",
                ("provide_policy", "set_feature_absent"),
                "provide_policy",
                tuple(feature_evidence[feature]),
            )
        )
    observed_mapper = next(iter(observed_response_mappers), None)
    if (
        expectations["schema"] == "required"
        and observed_mapper is not None
        and (len(observed_response_mappers) > 1 or observed_mapper != "from_internal")
        and not policy.response_mapper_explicit
    ):
        questions.append(
            InitQuestion(
                "policy.schema_mapper",
                "프로젝트 전체에서 사용할 Response 변환 메서드 하나를 선택하세요.",
                observed_response_mappers,
                observed_mapper,
                observed_response_mappers,
            )
        )
    return tuple(questions)


def _role_question(observation: InitRoleObservation) -> InitQuestion:
    return InitQuestion(
        f"role.{observation.path}",
        f"{observation.path}의 역할 근거가 충돌합니다. "
        "책임을 분리하거나 역할에 맞는 위치로 옮기세요.",
        observation.candidates,
        observation.recommended,
        tuple(
            f"{item.kind}:{item.value} -> {item.role} ({item.confidence})"
            for item in observation.evidence
        ),
    )
