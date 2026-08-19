from __future__ import annotations

import hashlib
import json

from taut.analysis.contracts import AdapterIdentity
from taut.configuration.model import ProjectConfiguration
from taut.policy.registry import RuleRegistry


def build_decision_digest(
    configuration: ProjectConfiguration,
    registry: RuleRegistry,
    adapter: AdapterIdentity,
) -> str:
    payload = {
        "configuration": configuration.digest(),
        "adapter": {"name": adapter.name, "version": adapter.version},
        "rules": [
            {
                "id": rule_id.value,
                "behavior_version": definition.behavior_version,
                "level": definition.default_level.value,
                "zones": sorted(zone.value for zone in definition.applies_to_zones),
            }
            for rule_id, definition in registry.definitions.items()
        ],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
