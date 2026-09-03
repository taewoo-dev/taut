from __future__ import annotations

from pathlib import Path

import pytest

from taut.loading.errors import PolicyConfigError
from taut.workspace import (
    discover_independent_projects,
    load_workspace,
    member_has_configuration,
    workspace_toml,
    write_workspace_manifest,
)


def _member(root: Path, name: str, *, configured: bool = True) -> Path:
    member = root / name
    member.mkdir(parents=True)
    tool = "\n[tool.taut]\nstrict = false\n" if configured else ""
    (member / "pyproject.toml").write_text(f'[project]\nname = "{name}"\nversion = "1"\n{tool}')
    (member / "app.py").write_text("value = 1\n")
    return member


def test_load_workspace_is_explicit_and_members_are_sorted(tmp_path: Path) -> None:
    assert load_workspace(tmp_path) is None
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "root"\nversion = "1"\n')
    assert load_workspace(tmp_path) is None
    _member(tmp_path, "backend")
    _member(tmp_path, "ai")
    (tmp_path / "pyproject.toml").write_text(
        '[tool.taut.workspace]\nschema_version = 1\nmembers = ["backend", "ai"]\n'
    )

    workspace = load_workspace(tmp_path)

    assert workspace is not None
    assert tuple(member.path for member in workspace.members) == ("ai", "backend")


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ('[tool.taut]\nstrict = true\n[tool.taut.workspace]\nmembers = ["app"]\n', "cannot also"),
        ('[tool.taut.workspace]\nunknown = true\nmembers = ["app"]\n', "unknown"),
        ('[tool.taut.workspace]\nschema_version = 2\nmembers = ["app"]\n', "schema_version"),
        ("[tool.taut.workspace]\nmembers = []\n", "non-empty"),
        ("[tool.taut.workspace]\nmembers = [1]\n", "only paths"),
        ('[tool.taut.workspace]\nmembers = ["app", "app"]\n', "unique"),
        ('[tool.taut.workspace]\nmembers = ["../app"]\n', "safe normalized"),
        ('[tool.taut.workspace]\nmembers = ["missing"]\n', "directory is missing"),
    ],
)
def test_load_workspace_rejects_ambiguous_or_invalid_manifests(
    tmp_path: Path, body: str, message: str
) -> None:
    _member(tmp_path, "app")
    (tmp_path / "pyproject.toml").write_text(body)

    with pytest.raises(PolicyConfigError, match=message):
        load_workspace(tmp_path)


def test_load_workspace_rejects_missing_manifest_and_overlapping_members(tmp_path: Path) -> None:
    app = tmp_path / "app"
    nested = app / "nested"
    nested.mkdir(parents=True)
    (nested / "pyproject.toml").write_text("")
    (tmp_path / "pyproject.toml").write_text(
        '[tool.taut.workspace]\nmembers = ["app", "app/nested"]\n'
    )
    with pytest.raises(PolicyConfigError, match="has no pyproject"):
        load_workspace(tmp_path)

    (app / "pyproject.toml").write_text("")
    with pytest.raises(PolicyConfigError, match="cannot overlap"):
        load_workspace(tmp_path)


def test_independent_project_discovery_ignores_noise_and_respects_root_ownership(
    tmp_path: Path,
) -> None:
    _member(tmp_path, "backend")
    _member(tmp_path, "ai")
    for directory in (".venv", ".direnv", ".research", "node_modules"):
        ignored = tmp_path / directory / "fake"
        ignored.mkdir(parents=True)
        (ignored / "pyproject.toml").write_text("")
        (ignored / "fake.py").write_text("")

    assert discover_independent_projects(tmp_path) == ("ai", "backend")

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "owned"\n')
    assert discover_independent_projects(tmp_path) == ()


def test_workspace_manifest_write_preserves_root_metadata_and_is_not_repeatable(
    tmp_path: Path,
) -> None:
    _member(tmp_path, "backend")
    (tmp_path / "pyproject.toml").write_text("[tool.ruff]\nline-length = 100\n")

    write_workspace_manifest(tmp_path, ("backend",))

    content = (tmp_path / "pyproject.toml").read_text()
    assert "[tool.ruff]" in content
    assert workspace_toml(("backend",)) in content
    assert member_has_configuration(tmp_path, "backend")
    assert not member_has_configuration(tmp_path, "missing")
    with pytest.raises(PolicyConfigError, match="already exists"):
        write_workspace_manifest(tmp_path, ("backend",))
