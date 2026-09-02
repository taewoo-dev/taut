"""Reviewable file-size budgets for onboarding."""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from taut.loading.errors import PolicyConfigError
from taut.onboarding_roles import InitRoleObservation


@dataclass(frozen=True)
class InitSizePolicy:
    default_max_lines: int
    role_max_lines: tuple[tuple[str, int], ...]
    resolved: bool
    source: str

    def json_payload(self) -> dict[str, object]:
        return {
            "recommended_default_max_lines": self.default_max_lines,
            "recommended_role_max_lines": dict(self.role_max_lines),
            "decision_source": self.source,
        }

    def evidence(self) -> tuple[str, ...]:
        values = [f"default={self.default_max_lines}"]
        values.extend(f"{role}={maximum}" for role, maximum in self.role_max_lines)
        return tuple(values)


def size_policy(
    root: Path,
    observations: tuple[InitRoleObservation, ...],
    answers: dict[str, object] | None,
) -> InitSizePolicy:
    recommended = _recommended(root, observations)
    if answers is None or "size" not in answers:
        return recommended
    raw = answers["size"]
    if not isinstance(raw, dict):
        raise PolicyConfigError("init answers.size must be an object")
    table = cast(dict[object, object], raw)
    if not all(isinstance(key, str) for key in table):
        raise PolicyConfigError("init answers.size keys must be strings")
    values = {cast(str, key): value for key, value in table.items()}
    unknown = set(values).difference({"accept_observed", "default_max_lines", "role_max_lines"})
    if unknown:
        raise PolicyConfigError(f"unknown init size keys: {', '.join(sorted(unknown))}")
    accepted = values.get("accept_observed")
    has_explicit = "default_max_lines" in values or "role_max_lines" in values
    if accepted is True and has_explicit:
        raise PolicyConfigError("init size cannot accept observed and provide explicit budgets")
    if accepted is True:
        return InitSizePolicy(
            recommended.default_max_lines,
            recommended.role_max_lines,
            True,
            "accepted_observed",
        )
    if accepted not in (None, False):
        raise PolicyConfigError("init size.accept_observed must be a boolean")
    if not has_explicit:
        return recommended
    default = _positive_integer(values.get("default_max_lines"), "size.default_max_lines")
    raw_roles = values.get("role_max_lines", {})
    if not isinstance(raw_roles, dict):
        raise PolicyConfigError("init size.role_max_lines must be an object")
    role_values = cast(dict[object, object], raw_roles)
    roles: list[tuple[str, int]] = []
    known_roles = {item.recommended for item in observations}
    for role, maximum in role_values.items():
        if not isinstance(role, str) or role not in known_roles:
            raise PolicyConfigError(f"init size has unknown role: {role}")
        parsed = _positive_integer(maximum, f"size.role_max_lines.{role}")
        if parsed > default:
            raise PolicyConfigError("init role size budgets cannot exceed default_max_lines")
        roles.append((role, parsed))
    return InitSizePolicy(default, tuple(sorted(roles)), True, "explicit")


def render_size_lines(policy: InitSizePolicy) -> tuple[str, ...]:
    if not policy.role_max_lines:
        return ()
    return (
        "",
        "[tool.taut.role_max_lines]",
        *(f"{role} = {maximum}" for role, maximum in policy.role_max_lines),
    )


def _recommended(root: Path, observations: tuple[InitRoleObservation, ...]) -> InitSizePolicy:
    grouped: dict[str, list[int]] = {}
    for observation in observations:
        try:
            lines = len((root / observation.path).read_text(errors="replace").splitlines())
        except OSError:
            continue
        grouped.setdefault(observation.recommended, []).append(lines)
    default = 700
    caps = {role: min(_cap(values), default) for role, values in grouped.items()}
    role_caps = tuple(sorted((role, cap) for role, cap in caps.items() if cap < default))
    return InitSizePolicy(default, role_caps, False, "recommended")


def _cap(values: list[int]) -> int:
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * 0.95) - 1)
    with_headroom = max(200, math.ceil(ordered[index] * 1.2))
    return int(math.ceil(with_headroom / 50) * 50)


def _positive_integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise PolicyConfigError(f"init {label} must be a positive integer")
    return value
