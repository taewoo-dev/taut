from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from taut.domain.frozen import FrozenMap


class FeatureExpectation(StrEnum):
    REQUIRED = "required"
    ABSENT = "absent"


BUILTIN_ASSURANCE_FEATURES = (
    "api",
    "schema",
    "dto",
    "snapshot",
    "exception_registry",
    "enum",
    "database",
    "transaction",
    "external_calls",
    "security",
    "tests",
    "migrations",
    "scripts",
)


@dataclass(frozen=True, order=True)
class ScopeExclusion:
    patterns: tuple[str, ...]
    reason: str

    def __post_init__(self) -> None:
        if not self.patterns or any(not pattern.strip() for pattern in self.patterns):
            raise ValueError("scope exclusion requires non-empty patterns")
        if not self.reason.strip():
            raise ValueError("scope exclusion requires a reason")


@dataclass(frozen=True, order=True)
class AssuranceAssertion:
    domain: str
    kind: str
    target: str
    state: str
    reason: str

    def __post_init__(self) -> None:
        if self.domain not in BUILTIN_ASSURANCE_FEATURES:
            raise ValueError(f"unknown assurance assertion domain: {self.domain}")
        if self.kind not in {"path", "symbol"}:
            raise ValueError("assurance assertion kind must be path or symbol")
        if self.state != "not_applicable":
            raise ValueError("assurance assertion state must be not_applicable")
        if not self.target.strip() or not self.reason.strip():
            raise ValueError("assurance assertion target and reason cannot be empty")


@dataclass(frozen=True)
class AssuranceConfiguration:
    features: FrozenMap[str, FeatureExpectation]
    exclusions: tuple[ScopeExclusion, ...] = ()
    assertions: tuple[AssuranceAssertion, ...] = ()
    max_approvals: int = 0
    max_inline_ignores: int = 0

    def __post_init__(self) -> None:
        unknown = set(self.features).difference(BUILTIN_ASSURANCE_FEATURES)
        if unknown:
            raise ValueError(f"unknown assurance features: {', '.join(sorted(unknown))}")
        if self.max_approvals < 0 or self.max_inline_ignores < 0:
            raise ValueError("assurance exception budgets cannot be negative")
        if self.exclusions != tuple(sorted(set(self.exclusions))):
            raise ValueError("scope exclusions must be unique and sorted")
        if self.assertions != tuple(sorted(set(self.assertions))):
            raise ValueError("assurance assertions must be unique and sorted")

    @classmethod
    def non_strict_default(cls) -> AssuranceConfiguration:
        return cls(FrozenMap())

    @classmethod
    def all_absent(cls) -> AssuranceConfiguration:
        return cls(
            FrozenMap(
                (feature, FeatureExpectation.ABSENT) for feature in BUILTIN_ASSURANCE_FEATURES
            )
        )
