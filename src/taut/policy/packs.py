from __future__ import annotations

import re
from dataclasses import dataclass, replace
from importlib.metadata import entry_points, version
from typing import cast

from taut.analysis.framework.fastapi import FASTAPI_PROVIDER_ID, FastAPIProvider
from taut.analysis.providers import CapabilitySpec, FactProviderV1
from taut.domain.frozen import FrozenMap
from taut.domain.snapshot import AnalysisSnapshot
from taut.policy.registry import RuleRegistry
from taut.policy.rules import builtin_rule_registry

BACKEND_PACK_ID = "taut.backend"
PYTHON_CORE_PROVIDER_ID = "taut.python-core"
SYNTAX_CAPABILITY = "taut.syntax@1"
BINDING_CAPABILITY = "taut.bindings@1"
IMPORT_CAPABILITY = "taut.imports@1"
USE_CAPABILITY = "taut.uses@1"
_PLUGIN_ID = re.compile(r"^[a-z][a-z0-9_.-]+$")


@dataclass(frozen=True)
class RulePackV1:
    id: str
    version: str
    registry: RuleRegistry
    required_capabilities: frozenset[CapabilitySpec] = frozenset()

    def __post_init__(self) -> None:
        if _PLUGIN_ID.fullmatch(self.id) is None:
            raise ValueError(f"invalid rule pack id: {self.id!r}")
        if not self.version.strip():
            raise ValueError("rule pack version cannot be empty")


@dataclass(frozen=True)
class PythonCoreProvider:
    id: str = PYTHON_CORE_PROVIDER_ID
    version: str = version("pytaut")
    provides: frozenset[CapabilitySpec] = frozenset(
        {
            CapabilitySpec(SYNTAX_CAPABILITY),
            CapabilitySpec(BINDING_CAPABILITY),
            CapabilitySpec(IMPORT_CAPABILITY),
            CapabilitySpec(USE_CAPABILITY),
        }
    )

    def analyze(self, snapshot: AnalysisSnapshot) -> FrozenMap[str, tuple[object, ...]]:
        return FrozenMap(
            (
                (SYNTAX_CAPABILITY, tuple(snapshot.modules.values())),
                (BINDING_CAPABILITY, snapshot.relations.bindings),
                (IMPORT_CAPABILITY, snapshot.relations.import_edges),
                (USE_CAPABILITY, snapshot.relations.use_edges),
            )
        )


def builtin_backend_pack() -> RulePackV1:
    registry = builtin_rule_registry()
    definitions = (
        replace(
            definition,
            requirements=replace(
                definition.requirements,
                capabilities=_capabilities_for(definition.id.value),
            ),
        )
        for definition in registry.definitions.values()
    )
    return RulePackV1(
        BACKEND_PACK_ID,
        version("pytaut"),
        type(registry).build(definitions),
        frozenset(PythonCoreProvider().provides),
    )


def _capabilities_for(rule_id: str) -> frozenset[str]:
    imports = {"ARCH001", "ARCH002", "IMPORT001", "BOUNDARY002", "BOUNDARY003"}
    syntax_only = {"ARCH000", "SIZE001", "TEST001", "IGNORE001"}
    if rule_id in syntax_only:
        return frozenset({SYNTAX_CAPABILITY})
    if rule_id in imports:
        return frozenset({SYNTAX_CAPABILITY, IMPORT_CAPABILITY})
    return frozenset({SYNTAX_CAPABILITY, BINDING_CAPABILITY, USE_CAPABILITY})


def load_rule_pack(pack_id: str) -> RulePackV1:
    if pack_id == BACKEND_PACK_ID:
        return builtin_backend_pack()
    matches = tuple(
        point for point in entry_points(group="taut.rule_packs.v1") if point.name == pack_id
    )
    if len(matches) != 1:
        raise ValueError(f"unknown or ambiguous rule pack: {pack_id}")
    value = matches[0].load()()
    if not isinstance(value, RulePackV1) or value.id != pack_id:
        raise ValueError(f"invalid rule pack entry point: {pack_id}")
    return value


def load_fact_provider(provider_id: str) -> FactProviderV1:
    if provider_id == PYTHON_CORE_PROVIDER_ID:
        return PythonCoreProvider()
    if provider_id == FASTAPI_PROVIDER_ID:
        return FastAPIProvider()
    matches = tuple(
        point for point in entry_points(group="taut.fact_providers.v1") if point.name == provider_id
    )
    if len(matches) != 1:
        raise ValueError(f"unknown or ambiguous fact provider: {provider_id}")
    provider = matches[0].load()()
    if provider.id != provider_id:
        raise ValueError(f"invalid fact provider entry point: {provider_id}")
    return cast(FactProviderV1, provider)
