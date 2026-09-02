"""Question construction for the versioned onboarding contract."""

from __future__ import annotations

from dataclasses import dataclass

from taut.configuration.assurance import BUILTIN_ASSURANCE_FEATURES
from taut.onboarding_policy import InitPolicyAnswers, missing_policy_decisions
from taut.onboarding_roles import InitRoleObservation
from taut.onboarding_scope import InitSourceScope


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
    role_observations: tuple[InitRoleObservation, ...],
    role_overrides: dict[str, str],
    feature_answers: dict[str, str],
    expectations: dict[str, str],
    feature_evidence: dict[str, list[str]],
    policy: InitPolicyAnswers,
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
                "현재 import 관계에서 계산한 최소 allow 그래프를 초기 정책으로 사용할까요?",
                ("accept", "review"),
                "review",
                paths,
            )
        )
    for observation in role_observations:
        if observation.requires_review and observation.path not in role_overrides:
            questions.append(_role_question(observation))
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
    return tuple(questions)


def _role_question(observation: InitRoleObservation) -> InitQuestion:
    return InitQuestion(
        f"role.{observation.path}",
        f"{observation.path}의 역할 근거가 충돌합니다. 정확한 역할을 선택하세요.",
        observation.candidates,
        observation.recommended,
        tuple(
            f"{item.kind}:{item.value} -> {item.role} ({item.confidence})"
            for item in observation.evidence
        ),
    )
