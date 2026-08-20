from __future__ import annotations

import hashlib
import json

from taut.analysis.contracts import AdapterIdentity
from taut.analysis.providers import FactProviderV1
from taut.configuration.model import ProjectConfiguration
from taut.policy.packs import RulePackV1
from taut.policy.registry import RuleRegistry


def build_decision_digest(
    configuration: ProjectConfiguration,
    registry: RuleRegistry,
    adapter: AdapterIdentity,
    packs: tuple[RulePackV1, ...] = (),
    providers: tuple[FactProviderV1, ...] = (),
) -> str:
    payload = {
        "configuration": configuration.digest(),
        "adapter": {"name": adapter.name, "version": adapter.version},
        "packs": [{"id": pack.id, "version": pack.version} for pack in packs],
        "providers": [
            {
                "id": provider.id,
                "version": provider.version,
                "capabilities": sorted(spec.id for spec in provider.provides),
                "requires": sorted(
                    dependency.capability.id for dependency in getattr(provider, "requires", ())
                ),
            }
            for provider in sorted(providers, key=lambda item: (item.id, item.version))
        ],
        "rules": [
            {
                "id": rule_id.value,
                "behavior_version": definition.behavior_version,
                "level": definition.default_level.value,
                "effective_level": configuration.policy.setting(rule_id).level.value,
                "target": definition.target.value,
                "capabilities": sorted(definition.requirements.capabilities),
                "minimum_stage": definition.requirements.minimum_stage.value,
                "change_impact": definition.change_impact.value,
                "zones": sorted(zone.value for zone in definition.applies_to_zones),
            }
            for rule_id, definition in registry.definitions.items()
        ],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
