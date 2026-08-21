from __future__ import annotations

from dataclasses import dataclass

import pytest
from tests.utils.builders import analyze, make_source

from taut.analysis.providers import (
    CapabilitySpec,
    ProviderDependency,
    apply_fact_providers,
    apply_fact_providers_incremental,
)
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId
from taut.domain.snapshot import AnalysisSnapshot


def snap(text: str = "value = 1") -> AnalysisSnapshot:
    return analyze(make_source("app/a.py", text))


@dataclass
class FakeProvider:
    id: str
    capability: str
    version: str = "1"
    requires: tuple[ProviderDependency, ...] = ()
    calls: int = 0
    incremental_calls: int = 0
    value: object = "value"
    fail: bool = False
    wrong_key: bool = False

    @property
    def provides(self) -> frozenset[CapabilitySpec]:
        return frozenset({CapabilitySpec(self.capability)})

    def analyze(self, snapshot: AnalysisSnapshot) -> FrozenMap[str, tuple[object, ...]]:
        del snapshot
        self.calls += 1
        if self.fail:
            raise RuntimeError("boom")
        key = "example.wrong@1" if self.wrong_key else self.capability
        return FrozenMap({key: (self.value,)})

    def analyze_incremental(
        self,
        snapshot: AnalysisSnapshot,
        previous: FrozenMap[str, tuple[object, ...]],
        impacted: frozenset[ModuleId],
    ) -> FrozenMap[str, tuple[object, ...]]:
        del snapshot, previous, impacted
        self.incremental_calls += 1
        return FrozenMap({self.capability: (self.value,)})


@dataclass
class PlainProvider:
    id: str = "plain"
    capability: str = "example.plain@1"
    calls: int = 0

    @property
    def version(self) -> str:
        return "1"

    @property
    def provides(self) -> frozenset[CapabilitySpec]:
        return frozenset({CapabilitySpec(self.capability)})

    def analyze(self, snapshot: AnalysisSnapshot) -> FrozenMap[str, tuple[object, ...]]:
        del snapshot
        self.calls += 1
        return FrozenMap({self.capability: ("plain",)})


def incremental(
    current: AnalysisSnapshot, previous: AnalysisSnapshot, providers: tuple[object, ...]
) -> AnalysisSnapshot:
    return apply_fact_providers_incremental(current, providers, previous, frozenset())  # type: ignore[arg-type]


def test_matching_provenance_uses_hook_and_refreshes_source_hash() -> None:
    provider = FakeProvider("p", "example.value@1")
    previous = apply_fact_providers(snap(), (provider,))
    current = snap("value = 2")
    result = incremental(current, previous, (provider,))
    assert provider.incremental_calls == 1
    assert provider.calls == 1
    assert result.capability_provenance["example.value@1"].source_hash == current.inputs.value


def test_stale_provider_version_falls_back_to_full() -> None:
    previous_provider = FakeProvider("p", "example.value@1", version="1")
    previous = apply_fact_providers(snap(), (previous_provider,))
    provider = FakeProvider("p", "example.value@1", version="2")
    result = incremental(snap("value = 2"), previous, (provider,))
    assert provider.calls == 1
    assert provider.incremental_calls == 0
    assert result.capabilities["example.value@1"] == ("value",)


def test_plain_v1_falls_back_to_full() -> None:
    provider = PlainProvider()
    previous = apply_fact_providers(snap(), (provider,))
    incremental(snap("value = 2"), previous, (provider,))
    assert provider.calls == 2


def test_dependency_chain_sees_prior_capability() -> None:
    base = FakeProvider("base", "example.base@1", value="base")
    dependent = FakeProvider(
        "dependent",
        "example.dependent@1",
        requires=(ProviderDependency(CapabilitySpec("example.base@1")),),
    )
    result = apply_fact_providers(snap(), (dependent, base))
    assert result.capabilities["example.dependent@1"] == ("value",)
    assert base.calls == dependent.calls == 1


def test_missing_dependency_is_unavailable() -> None:
    provider = FakeProvider(
        "missing", "example.out@1", requires=(ProviderDependency(CapabilitySpec("example.none@1")),)
    )
    result = apply_fact_providers(snap(), (provider,))
    assert "example.out@1" in {item.name for item in result.coverage.unavailable_capabilities}
    assert provider.calls == 0


def test_duplicate_provider_id_raises() -> None:
    with pytest.raises(ValueError, match="provider ids must be unique"):
        apply_fact_providers(
            snap(), (FakeProvider("same", "example.a@1"), FakeProvider("same", "example.b@1"))
        )


def test_duplicate_capability_owner_raises() -> None:
    with pytest.raises(ValueError, match="more than one provider"):
        apply_fact_providers(
            snap(), (FakeProvider("a", "example.same@1"), FakeProvider("b", "example.same@1"))
        )


def test_wrong_supplied_key_becomes_unavailable() -> None:
    provider = FakeProvider("wrong", "example.expected@1", wrong_key=True)
    result = apply_fact_providers(snap(), (provider,))
    assert "example.expected@1" in {item.name for item in result.coverage.unavailable_capabilities}


def test_provider_exception_becomes_unavailable() -> None:
    provider = FakeProvider("broken", "example.broken@1", fail=True)
    result = apply_fact_providers(snap(), (provider,))
    assert "example.broken@1" in {item.name for item in result.coverage.unavailable_capabilities}


def test_removed_provider_capability_does_not_survive() -> None:
    old = FakeProvider("old", "example.removed@1")
    previous = apply_fact_providers(snap(), (old,))
    result = incremental(snap("value = 2"), previous, ())
    assert "example.removed@1" not in result.capabilities
    assert "example.removed@1" not in result.capability_provenance


def test_incremental_matches_full_result() -> None:
    previous_provider = FakeProvider("p", "example.value@1")
    previous = apply_fact_providers(snap(), (previous_provider,))
    incremental_provider = FakeProvider("p", "example.value@1")
    full_provider = FakeProvider("p", "example.value@1")
    current = snap("value = 2")
    assert incremental(current, previous, (incremental_provider,)) == apply_fact_providers(
        current, (full_provider,)
    )
