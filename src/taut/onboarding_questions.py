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
                "Use the source roots inferred from packaging metadata and Python paths?",
                ("accept", "override"),
                "override" if source_scope.conflicts else "accept",
                source_scope.question_evidence(),
            )
        )
    if not architecture_accepted:
        questions.append(
            InitQuestion(
                "architecture.accept_observed",
                "Review whether the current imports match the intended policy. "
                "Fix violations in the code first.",
                ("accept", "review"),
                "review",
                paths,
            )
        )
    for source, target in unresolved_architecture_edges:
        questions.append(
            InitQuestion(
                f"architecture.edge.{source}->{target}",
                f"Decide whether to allow the risky import edge {source} -> {target}.",
                ("allow_with_reason", "deny_with_reason"),
                "deny_with_reason",
                (f"{source}->{target}",),
            )
        )
    if not size.resolved:
        questions.append(
            InitQuestion(
                "size.accept_observed",
                "Use the initial per-role limits inferred from the current file size distribution?",
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
                f"Files under {parent} lack sufficient role evidence. "
                "Place code according to existing roles. "
                "For a new structure, review role_selectors that will apply consistently.",
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
                    f"Confirm the expected state of policy feature {name}.",
                    ("required", "absent"),
                    expectations[name],
                    tuple(feature_evidence[name]),
                )
            )
    for feature, required_values in missing_policy_decisions(expectations, policy):
        questions.append(
            InitQuestion(
                f"policy.{feature}",
                f"Provide exact values to activate {feature}: {required_values}.",
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
                "Choose one Response mapper method for the entire project.",
                observed_response_mappers,
                observed_mapper,
                observed_response_mappers,
            )
        )
    return tuple(questions)


def _role_question(observation: InitRoleObservation) -> InitQuestion:
    return InitQuestion(
        f"role.{observation.path}",
        f"Role evidence conflicts for {observation.path}. "
        "Separate responsibilities or move the code to the appropriate role.",
        observation.candidates,
        observation.recommended,
        tuple(
            f"{item.kind}:{item.value} -> {item.role} ({item.confidence})"
            for item in observation.evidence
        ),
    )
