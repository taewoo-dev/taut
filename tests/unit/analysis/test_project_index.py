from __future__ import annotations

from tests.utils.builders import analyze, make_source

from taut.analysis.contracts import ContextManagerProvider, ResolverSettings
from taut.analysis.semantic_model import SnapshotSemanticModel
from taut.domain.facts import GuardKind
from taut.domain.ids import ModuleId, SymbolId


def test_project_index_builds_symmetric_graph_and_cycle() -> None:
    first = make_source("app/a.py", "from app.b import value_b")
    second = make_source("app/b.py", "from app.a import value_a")

    snapshot = analyze(first, second)

    assert snapshot.project.imports[ModuleId("app.a")] == (ModuleId("app.b"),)
    assert snapshot.project.imported_by[ModuleId("app.b")] == (ModuleId("app.a"),)
    assert snapshot.project.cycles[0].modules == (ModuleId("app.a"), ModuleId("app.b"))
    assert tuple((edge.importer, edge.target) for edge in snapshot.project.cycles[0].edges) == (
        (ModuleId("app.a"), ModuleId("app.b")),
        (ModuleId("app.b"), ModuleId("app.a")),
    )


def test_type_checking_imports_are_excluded_from_runtime_graph() -> None:
    first = make_source(
        "app/a.py",
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from app.b import B",
    )
    second = make_source(
        "app/b.py",
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from app.a import A",
    )

    snapshot = analyze(first, second)

    assert snapshot.project.imports[ModuleId("app.a")] == ()
    assert snapshot.project.type_imports[ModuleId("app.a")] == (ModuleId("app.b"),)
    assert snapshot.project.cycles == ()
    assert snapshot.project.import_edges[0].context.guard is GuardKind.TYPE_CHECKING_ONLY


def test_cycle_reports_real_edges_instead_of_sorted_component() -> None:
    first = make_source("app/a.py", "import app.c")
    second = make_source("app/b.py", "import app.a")
    third = make_source("app/c.py", "import app.b")

    cycle = analyze(first, second, third).project.cycles[0]

    assert cycle.modules == (ModuleId("app.a"), ModuleId("app.c"), ModuleId("app.b"))
    assert tuple((edge.importer, edge.target) for edge in cycle.edges) == (
        (ModuleId("app.a"), ModuleId("app.c")),
        (ModuleId("app.c"), ModuleId("app.b")),
        (ModuleId("app.b"), ModuleId("app.a")),
    )


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


def test_semantic_model_canonicalizes_transitive_re_exports() -> None:
    origin = make_source("app/enums/status.py", "class Status:\n    pass")
    middle = make_source("app/enums/public.py", "from .status import Status as PublicStatus")
    package = make_source("app/enums/__init__.py", "from .public import PublicStatus as Status")
    model = SnapshotSemanticModel(analyze(package, middle, origin))

    assert model.canonical_symbol(SymbolId("app.enums.Status")) == SymbolId(
        "app.enums.status.Status"
    )
    assert model.canonical_symbol(SymbolId("app.enums.public.PublicStatus")) == SymbolId(
        "app.enums.status.Status"
    )
    assert model.canonical_symbol(SymbolId("app.enums.status.Status")) == SymbolId(
        "app.enums.status.Status"
    )
    assert model.canonical_symbol(SymbolId("app.enums.Status.ACTIVE")) == SymbolId(
        "app.enums.status.Status.ACTIVE"
    )


def test_re_export_canonicalization_respects_final_module_binding() -> None:
    origin = make_source("app/status.py", "class Status:\n    pass")
    facade = make_source(
        "app/facade.py",
        "from .status import Status\nStatus = object()",
    )
    model = SnapshotSemanticModel(analyze(facade, origin))

    assert model.canonical_symbol(SymbolId("app.facade.Status")) == SymbolId("app.facade.Status")


def test_re_export_canonicalization_uses_a_later_import_binding() -> None:
    origin = make_source("app/status.py", "class Status:\n    pass")
    facade = make_source(
        "app/facade.py",
        "class Status:\n    pass\nfrom .status import Status",
    )
    model = SnapshotSemanticModel(analyze(facade, origin))

    assert model.canonical_symbol(SymbolId("app.facade.Status")) == SymbolId("app.status.Status")


def test_re_export_cycles_do_not_claim_a_canonical_symbol() -> None:
    first = make_source("app/a.py", "from .b import Value")
    second = make_source("app/b.py", "from .a import Value")
    model = SnapshotSemanticModel(analyze(first, second))

    assert model.canonical_symbol(SymbolId("app.a.Value")) == SymbolId("app.a.Value")
    assert model.canonical_symbol(SymbolId("app.b.Value")) == SymbolId("app.b.Value")
