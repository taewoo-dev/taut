from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest
from tests.utils.config import assurance_toml

from taut.check_runtime import prepare_check_runtime
from taut.check_service import CheckRequest, ResidentCheckSession, run_check_request
from taut.cli import main
from taut.domain.location import ConfigPath
from taut.loading.config_loader import load_project_configuration
from taut.loading.config_simplification import semantic_digest, simplify_configuration


def write_project(root: Path) -> Path:
    (root / "app/services").mkdir(parents=True)
    (root / "app/services/first.py").write_text("VALUE = 1\n")
    path = root / "pyproject.toml"
    path.write_text(
        '[project]\nname="sample"\nversion="0.1.0"\n'
        '[tool.taut]\nschema_version=5\nstrict=true\npacks=["taut.backend"]\n'
        'source_roots=["."]\ninclude=["app/*.py", "app/**/*.py"]\n'
        '[tool.taut.roles]\nservice=["app/services/*.py", "app/services/**/*.py"]\n'
        '[tool.taut.allow]\nservice=["service"]\n'
        '[tool.taut.code_conventions]\nservice_roles=["service"]\n'
        'response_mapper_name="from_internal"\n'
        "[tool.taut.assurance]\nmax_approvals=0\nmax_inline_ignores=0\n"
        + assurance_toml(pyproject=True)
    )
    return path


def test_simplify_is_read_only_equivalent_and_idempotent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_project(tmp_path)
    before = path.read_bytes()
    config = prepare_check_runtime(tmp_path).config
    assert main(["config", "simplify", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert path.read_bytes() == before
    section = tomllib.loads(output)["tool"]["taut"]
    assert "strict" not in section
    assert "packs" not in section
    assert "source_roots" not in section
    # Discovery uses Path.glob, while roles use fnmatchcase. Scope must not shrink.
    assert section["include"] == ["app/*.py", "app/**/*.py"]
    assert section["roles"]["service"] == ["app/services/*.py"]
    proposed = tmp_path / "compact.toml"
    proposed.write_text(output)
    compact = load_project_configuration(tmp_path, ConfigPath("compact.toml"))
    assert semantic_digest(compact) == semantic_digest(config)
    assert simplify_configuration(tmp_path, ConfigPath("compact.toml"), compact) == output
    assert run_check_request(CheckRequest(tmp_path, ConfigPath("compact.toml"))).exit_code == 0


def test_explain_uses_actual_scope_priority_and_inherited_origins(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_project(tmp_path)
    base = tmp_path / "base.toml"
    base.write_bytes(path.read_bytes())
    (tmp_path / "app/services/workflows").mkdir()
    target = tmp_path / "app/services/workflows/new.py"
    target.write_text("VALUE = 2\n")
    path.write_text(
        '[tool.taut]\nextend="base.toml"\nmax_lines=999\n'
        '[tool.taut.roles.workflow]\ninclude=["app/services/workflows/*.py"]\npriority=10\n'
        '[tool.taut.allow]\nworkflow=["service", "workflow"]\n'
    )
    assert (
        main(["config", "explain", str(tmp_path), "--path", str(target), "--format", "json"]) == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["path"]["role"] == "workflow"
    assert payload["path"]["allowed_imports"] == ["service", "workflow"]
    assert len(payload["path"]["matching_selectors"]) == 2
    assert payload["origins"]["max_lines"] == str(path)
    assert payload["origins"]["roles.service"] == str(base)
    assert "allowed_imports" in payload["effective_policy"]
    # An include pattern with one star does not discover nested files.
    path.write_text(
        path.read_text().replace("max_lines=999", 'max_lines=999\ninclude=["app/*.py"]')
    )
    assert (
        main(["config", "explain", str(tmp_path), "--path", str(target), "--format", "json"]) == 2
    )
    assert not json.loads(capsys.readouterr().out)["path"]["in_scope"]


def test_simplify_preserves_explicit_cache_behavior(tmp_path: Path) -> None:
    path = write_project(tmp_path)
    path.write_text(
        path.read_text() + '\n[tool.taut.cache]\nenabled=false\ndirectory=".other_cache"\n'
    )
    original = prepare_check_runtime(tmp_path).config
    output = simplify_configuration(tmp_path, None, original)
    cache = tomllib.loads(output)["tool"]["taut"]["cache"]
    assert cache == {"enabled": False, "directory": ".other_cache"}


def test_fixed_config_covers_add_rename_split_delete_and_rejects_unknown(tmp_path: Path) -> None:
    path = write_project(tmp_path)
    original = path.read_bytes()
    session = ResidentCheckSession(tmp_path)

    def check(expected: int) -> None:
        warm = session.check(CheckRequest(tmp_path, output_format="json"))
        cold = run_check_request(CheckRequest(tmp_path, output_format="json"))
        assert warm.exit_code == cold.exit_code == expected
        assert warm.stdout == cold.stdout
        assert path.read_bytes() == original

    check(0)
    new = tmp_path / "app/services/new.py"
    new.write_text("VALUE = 2\n")
    check(0)
    new = new.rename(tmp_path / "app/services/renamed.py")
    check(0)
    nested = tmp_path / "app/services/nested"
    nested.mkdir()
    new = new.rename(nested / "piece.py")
    check(0)
    new.unlink()
    check(0)
    unknown = tmp_path / "app/misplaced.py"
    unknown.write_text("VALUE = 3\n")
    check(2)
    result = run_check_request(CheckRequest(tmp_path, output_format="json"))
    assert "ROLE_UNCLASSIFIED" in result.stdout.decode()
    assert "app/services/*.py" in result.stdout.decode()


def test_new_files_do_not_gain_permission_from_their_contents(tmp_path: Path) -> None:
    path = write_project(tmp_path)
    path.write_text(path.read_text() + '\n[tool.taut.external]\nlogged_calls=["httpx.get"]\n')
    file = tmp_path / "app/services/new.py"
    for source, rule in (
        ("from datetime import datetime\nvalue = datetime.now()\n", "TIME001"),
        ('import httpx\nhttpx.get("https://example.com", timeout=1)\n', "LOG001"),
    ):
        file.write_text(source)
        result = run_check_request(CheckRequest(tmp_path, output_format="json"))
        assert any(finding.rule_id.value == rule for finding in result.findings)
        assert result.exit_code != 0


def test_shared_enum_package_accepts_new_modules_but_not_sibling_packages(tmp_path: Path) -> None:
    path = write_project(tmp_path)
    path.write_text(
        path.read_text()
        .replace('enum = "absent"', 'enum = "required"')
        .replace("[tool.taut.roles]\n", '[tool.taut.roles]\nenum=["app/enums/*.py"]\n')
        .replace("[tool.taut.allow]\n", '[tool.taut.allow]\nenum=["enum"]\n')
        + '\n[tool.taut.enum]\nshared_modules=["app.enums"]\n'
    )
    directory = tmp_path / "app/enums"
    directory.mkdir()
    code = 'from enum import StrEnum\nclass Status(StrEnum):\n    OPEN = "open"\n'
    (directory / "first.py").write_text(code)
    assert run_check_request(CheckRequest(tmp_path)).exit_code == 0
    (directory / "new.py").write_text(code)
    assert run_check_request(CheckRequest(tmp_path)).exit_code == 0
    (tmp_path / "app/services/misplaced.py").write_text(code)
    result = run_check_request(CheckRequest(tmp_path, output_format="json"))
    assert result.exit_code == 1
    assert any(finding.message_key == "enum.shared_location" for finding in result.findings)


def test_new_router_and_transaction_participant_keep_their_restrictions(tmp_path: Path) -> None:
    path = write_project(tmp_path)
    path.write_text(
        path.read_text()
        .replace(
            "[tool.taut.roles]\n",
            '[tool.taut.roles]\nrouter=["app/apis/*.py"]\nquery=["app/queries/*.py"]\n',
        )
        .replace(
            "[tool.taut.allow]\n",
            '[tool.taut.allow]\nrouter=["router", "service"]\nquery=["query"]\n',
        )
        + '\n[tool.taut.transaction]\nparticipant_roles=["service"]\n'
    )
    for name in ("apis", "queries"):
        (tmp_path / "app" / name).mkdir()
    (tmp_path / "app/queries/lookup.py").write_text("VALUE = 1\n")
    (tmp_path / "app/apis/new.py").write_text("from app.queries.lookup import VALUE\n")
    (tmp_path / "app/services/new.py").write_text(
        "from sqlalchemy.ext.asyncio import AsyncSession\n"
        "async def save(session: AsyncSession) -> None:\n    await session.commit()\n"
    )
    result = run_check_request(CheckRequest(tmp_path))
    rules = {finding.rule_id.value for finding in result.findings}
    assert {"ARCH001", "TX001", "SESSION003"}.issubset(rules)
