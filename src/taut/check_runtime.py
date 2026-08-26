"""Configuration and extension composition for one canonical check runtime."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from taut.analysis.providers import FactProviderV1
from taut.analysis.python.language_adapter import PythonAstAdapter
from taut.configuration.model import ProjectConfiguration
from taut.domain.frozen import FrozenMap
from taut.domain.location import ConfigPath
from taut.loading.config_loader import load_configuration_bootstrap, load_project_configuration
from taut.policy.decision_digest import build_decision_digest
from taut.policy.packs import RulePackV1, load_fact_provider, load_rule_pack
from taut.policy.registry import RuleRegistry


@dataclass(frozen=True)
class CheckRuntime:
    project_root: Path
    requested_config_path: ConfigPath | None
    config: ProjectConfiguration
    adapter: PythonAstAdapter
    providers: tuple[FactProviderV1, ...]
    packs: tuple[RulePackV1, ...]
    registry: RuleRegistry
    decision_digest: str

    @property
    def identity(self) -> tuple[object, ...]:
        return (
            self.config.digest(),
            self.adapter.identity,
            self.decision_digest,
            sys.version_info.major,
            sys.version_info.minor,
        )


def prepare_check_runtime(
    project_root: Path,
    config_path: ConfigPath | None = None,
) -> CheckRuntime:
    """Load extensions first, then validate configuration against their rule contracts."""
    root = project_root.resolve()
    bootstrap = load_configuration_bootstrap(root, config_path)
    providers = tuple(load_fact_provider(item) for item in bootstrap.providers)
    packs = tuple(load_rule_pack(item) for item in bootstrap.packs)
    registry = RuleRegistry.build(
        definition for pack in packs for definition in pack.registry.definitions.values()
    )
    rule_levels = FrozenMap(
        (rule_id, definition.default_level) for rule_id, definition in registry.definitions.items()
    )
    config = load_project_configuration(root, config_path, rule_levels=rule_levels)
    adapter = PythonAstAdapter()
    decision_digest = build_decision_digest(config, registry, adapter.identity, packs, providers)
    return CheckRuntime(
        root,
        config_path,
        config,
        adapter,
        providers,
        packs,
        registry,
        decision_digest,
    )
