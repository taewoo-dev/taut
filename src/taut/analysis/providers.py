from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Protocol

from taut.domain.frozen import FrozenMap
from taut.domain.snapshot import AnalysisSnapshot, UnavailableCapability

_CAPABILITY = re.compile(r"^[a-z][a-z0-9_.-]+@[1-9][0-9]*$")


@dataclass(frozen=True, order=True)
class CapabilitySpec:
    id: str

    def __post_init__(self) -> None:
        if _CAPABILITY.fullmatch(self.id) is None:
            raise ValueError(f"invalid capability id: {self.id!r}")


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
    unavailable = list(snapshot.coverage.unavailable_capabilities)
    for provider in providers:
        declared = frozenset(spec.id for spec in provider.provides)
        try:
            supplied = provider.analyze(snapshot)
            unexpected = set(supplied).difference(declared)
            missing = declared.difference(supplied)
            if unexpected or missing:
                raise ValueError("provider result does not match its declared capabilities")
            overlap = set(values).intersection(supplied)
            if overlap:
                raise ValueError("capability has more than one provider")
            values.update(supplied.items())
            snapshot = replace(snapshot, capabilities=FrozenMap(values.items()))
        except Exception as error:
            unavailable.extend(
                UnavailableCapability(spec.id, f"{provider.id}: {error.__class__.__name__}")
                for spec in provider.provides
            )
    coverage = replace(
        snapshot.coverage,
        unavailable_capabilities=tuple(sorted(set(unavailable))),
    )
    return replace(snapshot, capabilities=FrozenMap(values.items()), coverage=coverage)
