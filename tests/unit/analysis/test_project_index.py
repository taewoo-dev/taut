from __future__ import annotations

from tests.utils.builders import analyze, make_source

from taut.analysis.contracts import ContextManagerProvider, ResolverSettings
from taut.analysis.semantic_model import SnapshotSemanticModel
from taut.domain.ids import ModuleId, SymbolId


def test_project_index_builds_symmetric_graph_and_cycle() -> None:
    first = make_source("app/a.py", "from app.b import value_b")
    second = make_source("app/b.py", "from app.a import value_a")

    snapshot = analyze(first, second)

    assert snapshot.project.imports[ModuleId("app.a")] == (ModuleId("app.b"),)
    assert snapshot.project.imported_by[ModuleId("app.b")] == (ModuleId("app.a"),)
    assert snapshot.project.cycles[0].modules == (ModuleId("app.a"), ModuleId("app.b"))


def test_relative_import_is_resolved_from_package() -> None:
    package = make_source("app/__init__.py", "from .service import run")
    service = make_source("app/service.py", "def run():\n    return 1")

    snapshot = analyze(package, service)

    assert snapshot.project.imports[ModuleId("app")] == (ModuleId("app.service"),)
    assert snapshot.project.unresolved_imports == ()


def test_same_analysis_inputs_produce_same_snapshot_id() -> None:
    source = make_source("app/a.py", "value = 1")

    first = analyze(source)
    second = analyze(source)

    assert first.id == second.id
    assert first.project == second.project


def test_resolver_input_changes_snapshot_id() -> None:
    source = make_source("app/a.py", "value = 1")
    resolver = ResolverSettings(
        context_manager_providers=(
            ContextManagerProvider(SymbolId("app.database.session"), SymbolId("vendor.Session")),
        )
    )

    without_provider = analyze(source)
    with_provider = analyze(source, resolver=resolver)

    assert without_provider.id != with_provider.id


def test_internal_unresolved_import_is_not_silently_treated_as_external() -> None:
    source = make_source("app/a.py", "from app.missing import value")

    snapshot = analyze(source)

    assert snapshot.project.unresolved_imports[0].written_name == "app.missing.value"


def test_self_import_is_reported_as_cycle() -> None:
    source = make_source("app/a.py", "from app.a import value")

    snapshot = analyze(source)

    assert snapshot.project.cycles[0].modules == (ModuleId("app.a"),)


def test_semantic_model_exposes_read_only_project_views() -> None:
    first = make_source("app/a.py", "from app.b import value")
    second = make_source("app/b.py", "value = 1")
    model = SnapshotSemanticModel(analyze(first, second))

    assert model.imported_by(ModuleId("app.b")) == (ModuleId("app.a"),)
    assert model.calls_in(ModuleId("app.a")) == ()
    assert model.unresolved_imports() == ()
