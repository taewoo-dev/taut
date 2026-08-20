from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Protocol, TypeVar

from taut.domain.frozen import FrozenMap
from taut.domain.provenance import Provenance
from taut.domain.snapshot import AnalysisSnapshot, UnavailableCapability

_CAPABILITY = re.compile(r"^[a-z][a-z0-9_.-]+@[1-9][0-9]*$")
_VERSION = re.compile(
    r"^(?:0|[1-9][0-9]*|(?:0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)$"
)
T = TypeVar("T")


@dataclass(frozen=True, order=True)
class CapabilitySpec:
    id: str

    def __post_init__(self) -> None:
        if _CAPABILITY.fullmatch(self.id) is None:
            raise ValueError(f"invalid capability id: {self.id!r}")

    @property
    def name(self) -> str:
        return self.id.rsplit("@", 1)[0]

    @property
    def major(self) -> int:
        return int(self.id.rsplit("@", 1)[1])

    def accepts(self, provided: CapabilitySpec) -> bool:
        return self.name == provided.name and self.major == provided.major


@dataclass(frozen=True)
class CapabilityPayload[T]:
    """A typed, versioned capability value exposed by a provider."""

    capability: CapabilitySpec
    value: T
    provenance: Provenance

    def __post_init__(self) -> None:
        if not self.capability.id:
            raise ValueError("capability payload requires a capability")


@dataclass(frozen=True, order=True)
class ProviderDependency:
    capability: CapabilitySpec
    optional: bool = False


def _provider_requires(provider: object) -> tuple[ProviderDependency, ...]:
    raw = getattr(provider, "requires", ())
    return tuple(
        item if isinstance(item, ProviderDependency) else ProviderDependency(item) for item in raw
    )


class FactProviderV1(Protocol):
    @property
    def id(self) -> str: ...

    @property
    def version(self) -> str: ...

    @property
    def provides(self) -> frozenset[CapabilitySpec]: ...

    def analyze(self, snapshot: AnalysisSnapshot) -> FrozenMap[str, tuple[object, ...]]: ...


def apply_fact_providers(
    snapshot: AnalysisSnapshot,
    providers: tuple[FactProviderV1, ...],
) -> AnalysisSnapshot:
    values: dict[str, tuple[object, ...]] = dict(snapshot.capabilities.items())
    provenance = dict(snapshot.capability_provenance.items())
    unavailable = list(snapshot.coverage.unavailable_capabilities)
    ordered = _order_providers(providers)
    provider_ids = [provider.id for provider in ordered]
    if len(provider_ids) != len(set(provider_ids)):
        raise ValueError("fact provider ids must be unique")
    owners: dict[str, str] = {}
    for provider in ordered:
        if not provider.id.strip() or _VERSION.fullmatch(provider.version) is None:
            raise ValueError(f"invalid fact provider version: {provider.id!r} {provider.version!r}")
        declared = frozenset(spec.id for spec in provider.provides)
        duplicate = next((name for name in declared if name in owners), None)
        if duplicate is not None:
            raise ValueError(
                f"capability {duplicate!r} has more than one provider: "
                f"{owners[duplicate]!r} and {provider.id!r}"
            )
        owners.update((name, provider.id) for name in declared)
        missing_dependencies = tuple(
            dependency.capability.id
            for dependency in _provider_requires(provider)
            if not dependency.optional and not _has_compatible(values, dependency.capability)
        )
        if missing_dependencies:
            unavailable.extend(
                UnavailableCapability(
                    spec.id,
                    f"{provider.id}: unavailable; dependency cycle or missing capability; "
                    f"requires {', '.join(missing_dependencies)}",
                )
                for spec in provider.provides
            )
            continue
        try:
            supplied = provider.analyze(snapshot)
            unexpected = set(supplied).difference(declared)
            missing = declared.difference(supplied)
            if unexpected or missing:
                raise ValueError(
                    "provider result does not match declared capabilities "
                    f"(unexpected={sorted(unexpected)}, missing={sorted(missing)})"
                )
            overlap = set(values).intersection(supplied)
            if overlap:
                raise ValueError(f"capability has more than one provider: {sorted(overlap)}")
            values.update(supplied.items())
            for spec in provider.provides:
                provenance[spec.id] = Provenance(
                    provider=provider.id,
                    provider_version=provider.version,
                    source_hash=snapshot.inputs.value,
                    location=None,
                )
            snapshot = replace(snapshot, capabilities=FrozenMap(values.items()))
        except Exception as error:
            unavailable.extend(
                UnavailableCapability(
                    spec.id,
                    f"{provider.id}: failed ({error.__class__.__name__}: {error}); "
                    "install/configure a compatible provider or inspect its diagnostics",
                )
                for spec in provider.provides
            )
    coverage = replace(
        snapshot.coverage,
        unavailable_capabilities=tuple(sorted(set(unavailable))),
        capability_provenance=tuple(sorted(provenance.items())),
    )
    return replace(
        snapshot,
        capabilities=FrozenMap(values.items()),
        capability_provenance=FrozenMap(provenance.items()),
        coverage=coverage,
    )


def _has_compatible(values: dict[str, tuple[object, ...]], required: CapabilitySpec) -> bool:
    return any(required.accepts(CapabilitySpec(value)) for value in values)


def _order_providers(providers: tuple[FactProviderV1, ...]) -> tuple[FactProviderV1, ...]:
    """Topologically order providers, with stable id/version tie-breaking."""
    remaining = sorted(providers, key=lambda item: (item.id, item.version))
    result: list[FactProviderV1] = []
    available: set[str] = set()
    while remaining:
        ready = [
            provider
            for provider in remaining
            if all(
                dependency.optional
                or any(
                    dependency.capability.accepts(spec)
                    for prior in result
                    for spec in prior.provides
                )
                for dependency in _provider_requires(provider)
            )
        ]
        if not ready:
            result.extend(remaining)
            break
        provider = ready[0]
        remaining.remove(provider)
        result.append(provider)
        available.update(spec.id for spec in provider.provides)
    return tuple(result)
