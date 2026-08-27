from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from taut.configuration.assurance import AssuranceConfiguration
from taut.configuration.catalog import EffectCatalog
from taut.configuration.effective_policy import EffectivePolicy
from taut.configuration.manifest import ProjectManifest
from taut.domain.location import ProjectPath
from taut.domain.provider_ids import BUILTIN_BACKEND_PROVIDER_IDS


@dataclass(frozen=True)
class ProjectConfiguration:
    include: tuple[str, ...]
    exclude: tuple[str, ...]
    source_roots: tuple[ProjectPath, ...]
    manifest: ProjectManifest
    catalog: EffectCatalog
    policy: EffectivePolicy
    schema_version: int = 4
    packs: tuple[str, ...] = ("taut.backend",)
    providers: tuple[str, ...] = BUILTIN_BACKEND_PROVIDER_IDS
    strict: bool = True
    cache_enabled: bool = True
    cache_directory: ProjectPath = field(default_factory=lambda: ProjectPath(".taut_cache"))
    assurance: AssuranceConfiguration = field(
        default_factory=AssuranceConfiguration.non_strict_default
    )

    def __post_init__(self) -> None:
        if not self.include:
            raise ValueError("project include patterns cannot be empty")
        if not self.source_roots:
            raise ValueError("project source roots cannot be empty")
        if self.schema_version != 4:
            raise ValueError("project configuration schema must be 4")
        if not self.packs or len(self.packs) != len(set(self.packs)):
            raise ValueError("project rule packs must be non-empty and unique")
        if len(self.providers) != len(set(self.providers)):
            raise ValueError("project fact providers must be unique")

    def digest(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "packs": self.packs,
            "providers": self.providers,
            "strict": self.strict,
            "assurance": {
                "features": [
                    (name, expectation.value)
                    for name, expectation in self.assurance.features.items()
                ],
                "exclusions": [
                    {"patterns": item.patterns, "reason": item.reason}
                    for item in self.assurance.exclusions
                ],
                "assertions": [
                    {
                        "domain": item.domain,
                        "kind": item.kind,
                        "target": item.target,
                        "state": item.state,
                        "reason": item.reason,
                    }
                    for item in self.assurance.assertions
                ],
                "max_approvals": self.assurance.max_approvals,
                "max_inline_ignores": self.assurance.max_inline_ignores,
            },
            "include": self.include,
            "exclude": self.exclude,
            "source_roots": [path.value for path in self.source_roots],
            "roles": [
                {
                    "name": item.role.value,
                    "include": item.patterns,
                    "exclude": item.exclude,
                    "priority": item.priority,
                }
                for item in self.manifest.roles
            ],
            "zones": [
                {"name": item.zone.value, "patterns": item.patterns} for item in self.manifest.zones
            ],
            "default_zone": self.manifest.default_zone.value,
            "catalog": [
                {
                    "symbol": symbol.value,
                    "effects": sorted(effect.value for effect in entry.effects),
                    "access": entry.access_path.value,
                }
                for symbol, entry in self.catalog.entries.items()
            ],
            "policy": self.policy.digest(),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()
