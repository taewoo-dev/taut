from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

import pytest
from tests.utils.builders import analyze, make_source

import taut.plugins as public_plugins
import taut.semantic as public_semantic
from taut.analysis.providers import CapabilitySpec, FactProviderV1, apply_fact_providers
from taut.analysis.semantic_model import SnapshotSemanticModel
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId
from taut.domain.snapshot import AnalysisSnapshot
from taut.policy import packs


@dataclass(frozen=True)
class BrokenProvider:
    id: str = "broken"
    version: str = "1"
    provides: frozenset[CapabilitySpec] = frozenset({CapabilitySpec("example.broken@1")})

    def analyze(self, snapshot: AnalysisSnapshot) -> FrozenMap[str, tuple[object, ...]]:
        del snapshot
        raise RuntimeError("broken")


@dataclass(frozen=True)
class IncompleteProvider:
    id: str = "incomplete"
    version: str = "1"
    provides: frozenset[CapabilitySpec] = frozenset({CapabilitySpec("example.missing@1")})

    def analyze(self, snapshot: AnalysisSnapshot) -> FrozenMap[str, tuple[object, ...]]:
        del snapshot
        return FrozenMap()


@dataclass(frozen=True)
class EntryPoint:
    name: str
    value: object

    def load(self) -> Callable[[], object]:
        return lambda: self.value


def test_public_v1_facades_export_stable_contracts() -> None:
    assert public_plugins.CapabilitySpec is CapabilitySpec
    assert public_semantic.Binding is not None
    assert public_semantic.ProjectRelations is not None


def test_capability_and_pack_contracts_validate_identity() -> None:
    with pytest.raises(ValueError, match="invalid capability"):
        CapabilitySpec("Not Versioned")
    registry = packs.builtin_backend_pack().registry
    with pytest.raises(ValueError, match="invalid rule pack"):
        packs.RulePackV1("Invalid Pack", "1", registry)
    with pytest.raises(ValueError, match="version"):
        packs.RulePackV1("example.pack", " ", registry)


def test_builtin_pack_declares_capabilities_for_all_48_rules() -> None:
    pack = packs.load_rule_pack(packs.BACKEND_PACK_ID)

    assert len(pack.registry.definitions) == 48
    assert all(
        definition.requirements.capabilities for definition in pack.registry.definitions.values()
    )
    assert {spec.id for spec in pack.required_capabilities} == {
        packs.SYNTAX_CAPABILITY,
        packs.BINDING_CAPABILITY,
        packs.IMPORT_CAPABILITY,
        packs.USE_CAPABILITY,
    }


def test_provider_failure_is_explicit_coverage_not_a_crash() -> None:
    snapshot = analyze(make_source("app/a.py", "value = 1"))

    result = apply_fact_providers(snapshot, (BrokenProvider(), IncompleteProvider()))

    assert result.capabilities == FrozenMap()
    assert {item.name for item in result.coverage.unavailable_capabilities} == {
        "example.broken@1",
        "example.missing@1",
    }


def test_semantic_model_exposes_cached_project_relations() -> None:
    snapshot = analyze(
        make_source("app/a.py", "from app.b import run\nrun()"),
        make_source("app/b.py", "def run(): pass"),
    )
    model = SnapshotSemanticModel(snapshot)
    module_id = ModuleId("app.a")

    assert model.snapshot_id == snapshot.id
    assert model.bindings(module_id)
    assert model.bindings()
    assert model.uses(module_id)
    assert model.uses()
    assert model.import_edges_of(module_id)
    assert model.capabilities() == frozenset()


def test_explicit_entry_point_loading_is_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = packs.builtin_backend_pack()
    selected: tuple[EntryPoint, ...] = (EntryPoint("example.pack", backend),)

    def fake_entry_points(**kwargs: object) -> tuple[EntryPoint, ...]:
        del kwargs
        return selected

    monkeypatch.setattr(packs, "entry_points", fake_entry_points)
    with pytest.raises(ValueError, match="invalid rule pack"):
        packs.load_rule_pack("example.pack")

    selected = ()
    with pytest.raises(ValueError, match="unknown or ambiguous"):
        packs.load_rule_pack("missing.pack")
    with pytest.raises(ValueError, match="unknown or ambiguous"):
        packs.load_fact_provider("missing.provider")

    provider = packs.PythonCoreProvider(id="wrong")
    selected = (EntryPoint("example.provider", provider),)
    with pytest.raises(ValueError, match="invalid fact provider"):
        packs.load_fact_provider("example.provider")

    matching = packs.PythonCoreProvider(id="example.provider")
    selected = (EntryPoint("example.provider", matching),)
    assert packs.load_fact_provider("example.provider") == cast(FactProviderV1, matching)
