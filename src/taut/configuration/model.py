from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from taut.configuration.catalog import EffectCatalog
from taut.configuration.effective_policy import EffectivePolicy
from taut.configuration.manifest import ProjectManifest
from taut.domain.location import ProjectPath


@dataclass(frozen=True)
class ProjectConfiguration:
    include: tuple[str, ...]
    exclude: tuple[str, ...]
    source_roots: tuple[ProjectPath, ...]
    manifest: ProjectManifest
    catalog: EffectCatalog
    policy: EffectivePolicy
    schema_version: int = 3
    packs: tuple[str, ...] = ("taut.backend",)
    providers: tuple[str, ...] = ("taut.python-core",)

    def __post_init__(self) -> None:
        if not self.include:
            raise ValueError("project include patterns cannot be empty")
        if not self.source_roots:
            raise ValueError("project source roots cannot be empty")
        if self.schema_version != 3:
            raise ValueError("project configuration schema must be 3")
        if not self.packs or len(self.packs) != len(set(self.packs)):
            raise ValueError("project rule packs must be non-empty and unique")
        if len(self.providers) != len(set(self.providers)):
            raise ValueError("project fact providers must be unique")

    def digest(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "packs": self.packs,
            "providers": self.providers,
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
