from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from importlib.metadata import entry_points, version
from typing import Any, Protocol, cast

from taut.analysis.framework.fastapi import FASTAPI_PROVIDER_ID, FastAPIProvider
from taut.analysis.framework.pydantic import PYDANTIC_PROVIDER_ID, PydanticProvider
from taut.analysis.framework.sqlalchemy import SQLALCHEMY_PROVIDER_ID, SQLAlchemyProvider
from taut.analysis.providers import CapabilitySpec, FactProviderV1
from taut.configuration.model import ProjectConfiguration
from taut.domain.assurance import AssuranceIssue
from taut.domain.frozen import FrozenMap
from taut.domain.provider_ids import BUILTIN_BACKEND_PROVIDER_IDS as _BUILTIN_BACKEND_PROVIDER_IDS
from taut.domain.snapshot import AnalysisSnapshot
from taut.policy.registry import RuleRegistry
from taut.policy.rules import builtin_rule_registry

BACKEND_PACK_ID = "taut.backend"
PYTHON_CORE_PROVIDER_ID = "taut.python-core"
BUILTIN_BACKEND_PROVIDER_IDS = _BUILTIN_BACKEND_PROVIDER_IDS
SYNTAX_CAPABILITY = "taut.syntax@1"
BINDING_CAPABILITY = "taut.bindings@1"
IMPORT_CAPABILITY = "taut.imports@1"
USE_CAPABILITY = "taut.uses@1"
_PLUGIN_ID = re.compile(r"^[a-z][a-z0-9_.-]+$")


def _entry_points(group: str) -> tuple[Any, ...]:
    """Return a stable tuple across Python metadata API generations."""
    points: Any = entry_points()
    if hasattr(points, "select"):
        selected = points.select(group=group)
    elif hasattr(points, "get"):
        selected = points.get(group, ())
    else:
        selected = points
    return tuple(sorted(selected, key=lambda point: (point.name, point.value)))


def plugin_environment_digest() -> str:
    """Fingerprint installed extension entry points without importing their implementations."""
    values: list[dict[str, str]] = []
    for group in ("taut.rule_packs.v1", "taut.fact_providers.v1"):
        for point in _entry_points(group):
            distribution = getattr(point, "dist", None)
            metadata = getattr(distribution, "metadata", {})
            name = metadata.get("Name", "") if hasattr(metadata, "get") else ""
            values.append(
                {
                    "group": group,
                    "name": str(point.name),
                    "value": str(point.value),
                    "distribution": str(name),
                    "version": str(getattr(distribution, "version", "")),
                }
            )
    encoded = json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


class AssuranceAuditorV1(Protocol):
    @property
    def id(self) -> str: ...

    @property
    def version(self) -> str: ...

    @property
    def audited_rules(self) -> frozenset[str]: ...

    def audit(
        self, snapshot: AnalysisSnapshot, config: ProjectConfiguration
    ) -> tuple[AssuranceIssue, ...]: ...


@dataclass(frozen=True)
class RulePackV1:
    id: str
    version: str
    registry: RuleRegistry
    required_capabilities: frozenset[CapabilitySpec] = frozenset()
    assurance_auditor: AssuranceAuditorV1 | None = None

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

    def analyze_incremental(
        self,
        snapshot: AnalysisSnapshot,
        previous: FrozenMap[str, tuple[object, ...]],
        impacted: frozenset[object],
    ) -> FrozenMap[str, tuple[object, ...]]:
        return self.analyze(snapshot)


@dataclass(frozen=True)
class BuiltinBackendAssuranceAuditor:
    id: str = "taut.backend.assurance"
    version: str = "1"
    audited_rules: frozenset[str] = frozenset(
        rule_id.value for rule_id in builtin_rule_registry().definitions
    )

    def audit(
        self, snapshot: AnalysisSnapshot, config: ProjectConfiguration
    ) -> tuple[AssuranceIssue, ...]:
        del snapshot, config
        return ()


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
        BuiltinBackendAssuranceAuditor(),
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
    matches = tuple(point for point in _entry_points("taut.rule_packs.v1") if point.name == pack_id)
    if len(matches) != 1:
        raise ValueError(f"unknown or ambiguous rule pack: {pack_id}")
    try:
        value = matches[0].load()()
    except Exception as error:
        raise ValueError(f"failed to load rule pack entry point: {pack_id}: {error}") from error
    if not isinstance(value, RulePackV1) or value.id != pack_id:
        raise ValueError(f"invalid rule pack entry point: {pack_id}")
    return value


def load_fact_provider(provider_id: str) -> FactProviderV1:
    if provider_id == PYTHON_CORE_PROVIDER_ID:
        return PythonCoreProvider()
    if provider_id == FASTAPI_PROVIDER_ID:
        return FastAPIProvider()
    if provider_id == SQLALCHEMY_PROVIDER_ID:
        return SQLAlchemyProvider()
    if provider_id == PYDANTIC_PROVIDER_ID:
        return PydanticProvider()
    matches = tuple(
        point for point in _entry_points("taut.fact_providers.v1") if point.name == provider_id
    )
    if len(matches) != 1:
        raise ValueError(f"unknown or ambiguous fact provider: {provider_id}")
    try:
        provider = matches[0].load()()
    except Exception as error:
        raise ValueError(
            f"failed to load fact provider entry point: {provider_id}: {error}"
        ) from error
    if provider.id != provider_id:
        raise ValueError(f"invalid fact provider entry point: {provider_id}")
    return cast(FactProviderV1, provider)


def builtin_backend_providers() -> tuple[FactProviderV1, ...]:
    """Return the built-in backend providers in stable dependency order."""
    return tuple(load_fact_provider(provider_id) for provider_id in BUILTIN_BACKEND_PROVIDER_IDS)
