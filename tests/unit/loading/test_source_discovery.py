from __future__ import annotations

from pathlib import Path

from taut.configuration.model import ProjectConfiguration
from taut.domain.location import ProjectPath
from taut.loading.config_loader import default_project_configuration
from taut.loading.source_discovery import discover_sources


def test_source_discovery_records_included_and_excluded_files(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "service.py").write_text("value = 1")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "ignored.py").write_text("value = 2")

    result = discover_sources(tmp_path, default_project_configuration())

    assert tuple(source.path.value for source in result.sources) == ("app/service.py",)
    assert any(not entry.included for entry in result.report.entries)
    assert result.issues == ()


def test_source_discovery_normalizes_symlinked_temporary_root(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "service.py").write_text("value = 1")
    result = discover_sources(Path(str(tmp_path)), default_project_configuration())
    assert [source.path.value for source in result.sources] == ["app/service.py"]


def test_source_discovery_accepts_real_symlink_alias_root(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app").mkdir()
    (target / "app" / "service.py").write_text("value = 1")
    alias = tmp_path / "alias"
    alias.symlink_to(target, target_is_directory=True)
    result = discover_sources(alias, default_project_configuration())
    assert [source.path.value for source in result.sources] == ["app/service.py"]


def test_source_discovery_reports_missing_source_root(tmp_path: Path) -> None:
    base = default_project_configuration()
    config = ProjectConfiguration(
        base.include,
        base.exclude,
        (ProjectPath("missing"),),
        base.manifest,
        base.catalog,
        base.policy,
    )

    result = discover_sources(tmp_path, config)

    assert {issue.code for issue in result.issues} == {"SOURCE_ROOT_MISSING", "NO_SOURCES"}


def test_source_discovery_rejects_source_root_outside_project(tmp_path: Path) -> None:
    external = tmp_path.parent / f"{tmp_path.name}-external"
    external.mkdir()
    link = tmp_path / "external"
    link.symlink_to(external, target_is_directory=True)
    base = default_project_configuration()
    config = ProjectConfiguration(
        base.include,
        base.exclude,
        (ProjectPath("external"),),
        base.manifest,
        base.catalog,
        base.policy,
    )

    result = discover_sources(tmp_path, config)

    assert {issue.code for issue in result.issues} == {"SOURCE_ROOT_OUTSIDE", "NO_SOURCES"}


def test_source_discovery_assigns_stable_identity_to_non_importable_script_name(
    tmp_path: Path,
) -> None:
    (tmp_path / "bad-name.py").write_text("value = 1")

    first = discover_sources(tmp_path, default_project_configuration())
    second = discover_sources(tmp_path, default_project_configuration())

    assert first.issues == second.issues == ()
    assert first.sources[0].module_id == second.sources[0].module_id
    assert first.sources[0].module_id.value.startswith("bad_name_")


def test_source_discovery_reports_duplicate_module_across_roots(tmp_path: Path) -> None:
    for root_name in ("one", "two"):
        root = tmp_path / root_name / "app"
        root.mkdir(parents=True)
        (root / "service.py").write_text("value = 1")
    base = default_project_configuration()
    config = ProjectConfiguration(
        ("one/**/*.py", "two/**/*.py"),
        (),
        (ProjectPath("one"), ProjectPath("two")),
        base.manifest,
        base.catalog,
        base.policy,
    )

    result = discover_sources(tmp_path, config)

    issue = next(issue for issue in result.issues if issue.code == "SOURCE_MODULE_CONFLICT")
    assert "one/app/service.py (root one)" in issue.message
    assert "two/app/service.py (root two)" in issue.message


def test_source_discovery_uses_the_most_specific_overlapping_source_root(
    tmp_path: Path,
) -> None:
    package = tmp_path / "src" / "app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "service.py").write_text("value = 1")
    (tmp_path / "conftest.py").write_text("value = 2")
    base = default_project_configuration()
    config = ProjectConfiguration(
        ("*.py", "**/*.py"),
        (),
        (ProjectPath("."), ProjectPath("src")),
        base.manifest,
        base.catalog,
        base.policy,
    )

    result = discover_sources(tmp_path, config)

    assert result.issues == ()
    assert {source.path.value: source.module_id.value for source in result.sources} == {
        "conftest.py": "conftest",
        "src/app/__init__.py": "app",
        "src/app/service.py": "app.service",
    }
