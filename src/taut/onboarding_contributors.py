"""Public extension contract for framework-aware onboarding discovery."""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib.metadata import entry_points
from typing import Any, Protocol, cast

from taut.loading.errors import PolicyConfigError

ONBOARDING_ENTRY_POINT = "taut.onboarding_contributors.v1"
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]+$")


@dataclass(frozen=True, order=True)
class OnboardingFrameworkSpec:
    """Map imported top-level modules to the provider that understands them."""

    provider_id: str
    import_roots: tuple[str, ...]

    def __post_init__(self) -> None:
        if _IDENTIFIER.fullmatch(self.provider_id) is None:
            raise ValueError(f"invalid onboarding provider id: {self.provider_id!r}")
        if not self.import_roots or any(
            not root.isidentifier() or "." in root for root in self.import_roots
        ):
            raise ValueError("onboarding import_roots must be top-level Python identifiers")
        if tuple(sorted(set(self.import_roots))) != self.import_roots:
            raise ValueError("onboarding import_roots must be unique and sorted")


class OnboardingContributorV1(Protocol):
    @property
    def id(self) -> str: ...

    @property
    def version(self) -> str: ...

    @property
    def frameworks(self) -> tuple[OnboardingFrameworkSpec, ...]: ...


BUILTIN_FRAMEWORK_SPECS = (
    OnboardingFrameworkSpec("taut.fastapi", ("fastapi", "starlette")),
    OnboardingFrameworkSpec("taut.pydantic", ("pydantic",)),
    OnboardingFrameworkSpec("taut.pytest", ("pytest",)),
    OnboardingFrameworkSpec("taut.sqlalchemy", ("sqlalchemy",)),
    OnboardingFrameworkSpec("taut.tortoise", ("tortoise",)),
)


def onboarding_framework_specs() -> tuple[OnboardingFrameworkSpec, ...]:
    specs = list(BUILTIN_FRAMEWORK_SPECS)
    owners = {root: "taut.builtin" for spec in specs for root in spec.import_roots}
    for point in _entry_points():
        contributor = cast(OnboardingContributorV1, point.load()())
        if _IDENTIFIER.fullmatch(contributor.id) is None or not contributor.version.strip():
            raise PolicyConfigError(f"invalid onboarding contributor: {point.name}")
        raw_frameworks: object = contributor.frameworks
        for raw_spec in cast(tuple[object, ...], raw_frameworks):
            spec = raw_spec
            if not isinstance(spec, OnboardingFrameworkSpec):
                raise PolicyConfigError(
                    f"onboarding contributor {contributor.id} returned an invalid framework spec"
                )
            conflicts = sorted(set(spec.import_roots).intersection(owners))
            if conflicts:
                root = conflicts[0]
                raise PolicyConfigError(
                    f"onboarding import root {root!r} is owned by both "
                    f"{owners[root]} and {contributor.id}"
                )
            specs.append(spec)
            owners.update((root, contributor.id) for root in spec.import_roots)
    return tuple(sorted(specs))


def _entry_points() -> tuple[Any, ...]:
    points: Any = entry_points()
    selected = (
        points.select(group=ONBOARDING_ENTRY_POINT)
        if hasattr(points, "select")
        else points.get(ONBOARDING_ENTRY_POINT, ())
        if hasattr(points, "get")
        else points
    )
    return tuple(sorted(selected, key=lambda point: (point.name, point.value)))
