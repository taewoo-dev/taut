from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatchcase

from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId
from taut.domain.location import ConfigLocation
from taut.domain.snapshot import AnalysisSnapshot

_CLASSIFICATION_NAME = re.compile(r"^[a-z][a-z0-9_]*$")


@dataclass(frozen=True, order=True)
class Role:
    value: str

    def __post_init__(self) -> None:
        if not _CLASSIFICATION_NAME.fullmatch(self.value):
            raise ValueError(f"invalid role: {self.value!r}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, order=True)
class Zone:
    value: str

    def __post_init__(self) -> None:
        if not _CLASSIFICATION_NAME.fullmatch(self.value):
            raise ValueError(f"invalid zone: {self.value!r}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, order=True)
class RoleMatcher:
    role: Role
    patterns: tuple[str, ...]
    source: ConfigLocation
    exclude: tuple[str, ...] = ()
    priority: int = 0

    def matches(self, path: str) -> bool:
        return any(fnmatchcase(path, pattern) for pattern in self.patterns) and not any(
            fnmatchcase(path, pattern) for pattern in self.exclude
        )

    def __post_init__(self) -> None:
        if not self.patterns or any(not pattern.strip() for pattern in self.patterns):
            raise ValueError("role matcher requires non-empty patterns")
        if any(not pattern.strip() for pattern in self.exclude):
            raise ValueError("role matcher exclude patterns cannot be empty")


@dataclass(frozen=True, order=True)
class ZoneMatcher:
    zone: Zone
    patterns: tuple[str, ...]
    source: ConfigLocation

    def __post_init__(self) -> None:
        if not self.patterns or any(not pattern.strip() for pattern in self.patterns):
            raise ValueError("zone matcher requires non-empty patterns")


@dataclass(frozen=True, order=True)
class ModuleClassification:
    module: ModuleId
    role: Role | None
    zone: Zone
    role_source: ConfigLocation | None
    zone_source: ConfigLocation


@dataclass(frozen=True)
class ClassificationIndex:
    modules: FrozenMap[ModuleId, ModuleClassification]

    def get(self, module_id: ModuleId) -> ModuleClassification:
        return self.modules[module_id]


@dataclass(frozen=True)
class ProjectManifest:
    roles: tuple[RoleMatcher, ...]
    zones: tuple[ZoneMatcher, ...]
    default_zone: Zone
    source: ConfigLocation

    def placement_hint(self, roles: frozenset[Role] | None = None) -> str:
        paths = [
            f"{matcher.role.value}: "
            + next((p for p in matcher.patterns if "*" in p), matcher.patterns[0])
            for matcher in self.roles
            if roles is None or matcher.role in roles
        ]
        return "선언된 경로: " + "; ".join(paths)

    def role_for_path(self, path: str) -> RoleMatcher | None:
        matches = tuple(matcher for matcher in self.roles if matcher.matches(path))
        highest = max((matcher.priority for matcher in matches), default=None)
        selected = tuple(matcher for matcher in matches if matcher.priority == highest)
        if len(selected) > 1:
            names = ", ".join(matcher.role.value for matcher in selected)
            raise ValueError(f"{path}: 둘 이상의 role과 일치합니다: {names}")
        return selected[0] if selected else None

    def classify(self, snapshot: AnalysisSnapshot) -> ClassificationIndex:
        classifications: list[tuple[ModuleId, ModuleClassification]] = []
        for module_id, facts in snapshot.modules.items():
            path = facts.module.path.value
            selected_role = self.role_for_path(path)
            zone_matches = tuple(
                matcher
                for matcher in self.zones
                if any(fnmatchcase(path, pattern) for pattern in matcher.patterns)
            )
            if len(zone_matches) > 1:
                names = ", ".join(matcher.zone.value for matcher in zone_matches)
                raise ValueError(f"{path}: 둘 이상의 zone과 일치합니다: {names}")
            role = selected_role.role if selected_role else None
            role_source = selected_role.source if selected_role else None
            zone = zone_matches[0].zone if zone_matches else self.default_zone
            zone_source = zone_matches[0].source if zone_matches else self.source
            classifications.append(
                (
                    module_id,
                    ModuleClassification(
                        module=module_id,
                        role=role,
                        zone=zone,
                        role_source=role_source,
                        zone_source=zone_source,
                    ),
                )
            )
        return ClassificationIndex(FrozenMap(classifications))
