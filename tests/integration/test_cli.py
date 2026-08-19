from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from taut.cli import main


def _write_project(root: Path, content: str, *, role: str = "service") -> None:
    app = root / "app"
    app.mkdir()
    (app / "service.py").write_text(content)
    policy_dir = root / ".policy"
    policy_dir.mkdir()
    (policy_dir / "policy.toml").write_text(
        f"""
schema_version = 2
[project]
include = ["app/*.py"]
source_roots = ["."]
default_zone = "prod"
[[roles]]
name = "{role}"
patterns = ["app/*.py"]
[architecture.allow]
{role} = ["{role}"]
""".strip()
    )


def _write_pyproject_project(root: Path, content: str, *, strict: bool) -> None:
    app = root / "app"
    app.mkdir()
    (app / "service.py").write_text(content)
    (root / "pyproject.toml").write_text(
        f"""
[project]
name = "sample-service"
version = "0.1.0"

[tool.taut]
strict = {str(strict).lower()}
source_roots = ["."]

[tool.taut.roles]
service = ["app/*.py"]

[tool.taut.allow]
service = ["service"]
""".strip()
    )


@pytest.mark.integration
def test_cli_returns_one_and_text_diagnostic_for_violation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_project(tmp_path, "from datetime import datetime\nvalue = datetime.now()")

    code = main(["check", str(tmp_path)])
    output = capsys.readouterr().out

    assert code == 1
    assert "TIME001" in output
    assert "app/service.py:2" in output
    assert "error:" in output
    assert "검사 완료: 오류 1건, 경고 0건" in output
    assert "판정 기준:" not in output

    assert main(["check", str(tmp_path), "--verbose"]) == 1
    assert "판정 기준:" in capsys.readouterr().out

    assert main(["check", str(tmp_path), "--width", "60"]) == 1
    assert "\n    " in capsys.readouterr().out


@pytest.mark.integration
def test_cli_json_v2_is_deterministic_for_compliant_project(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_project(tmp_path, "value = 1")

    first_code = main(["check", str(tmp_path), "--format", "json"])
    first = capsys.readouterr().out
    second_code = main(["check", str(tmp_path), "--format", "json"])
    second = capsys.readouterr().out
    payload = cast(dict[str, object], json.loads(first))

    assert first_code == second_code == 0
    assert first == second
    assert payload["schema_version"] == 2
    assert payload["diagnostics"] == []
    assert len(cast(str, payload["decision_digest"])) == 64


@pytest.mark.integration
def test_pyproject_non_strict_mode_reports_without_failing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_pyproject_project(
        tmp_path,
        "from datetime import datetime\nvalue = datetime.now()",
        strict=False,
    )

    code = main(["check", str(tmp_path)])
    output = capsys.readouterr().out

    assert code == 0
    assert "warning:" in output
    assert "[TIME001]" in output


@pytest.mark.integration
def test_cli_invalid_or_missing_configuration_returns_two(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["check", str(tmp_path)]) == 2
    assert "configuration error" in capsys.readouterr().err

    policy_dir = tmp_path / ".policy"
    policy_dir.mkdir()
    (policy_dir / "policy.toml").write_text("schema_version = 1")
    assert main(["check", str(tmp_path)]) == 2
    assert "schema_version must be 2" in capsys.readouterr().err


@pytest.mark.integration
def test_cli_configuration_error_respects_json_format(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["check", str(tmp_path), "--format", "json"])
    payload = cast(dict[str, object], json.loads(capsys.readouterr().out))

    assert code == 2
    assert payload["schema_version"] == 2
    assert cast(dict[str, object], payload["exit"])["code"] == 2
    assert cast(list[dict[str, object]], payload["engine_issues"])[0]["code"] == (
        "INVALID_CONFIGURATION"
    )


@pytest.mark.integration
def test_config_validate_and_rule_explanation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_project(tmp_path, "value = 1")

    assert main(["config", "validate", str(tmp_path)]) == 0
    assert "설정 정상" in capsys.readouterr().out
    assert main(["rules", "ASYNC001"]) == 0
    explanation = capsys.readouterr().out
    assert "강도: enforced" in explanation
    assert "적용 영역:" in explanation


@pytest.mark.integration
def test_cli_accepts_absolute_config_for_read_only_external_audit(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write_project(project, "value = 1")
    external_config = tmp_path / "audit-policy.toml"
    external_config.write_text((project / ".policy" / "policy.toml").read_text())

    code = main(["check", str(project), "--config", str(external_config)])

    assert code == 0
    assert "검사 완료: 문제 없음" in capsys.readouterr().out


@pytest.mark.integration
def test_exact_inline_ignore_is_allowed_but_unused_or_malformed_is_not(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_project(
        tmp_path,
        "from datetime import datetime\nvalue = datetime.now()  # taut: ignore[TIME001]",
    )
    assert main(["check", str(tmp_path), "--verbose"]) == 0
    assert "ignore: 사용 1" in capsys.readouterr().out

    (tmp_path / "app" / "service.py").write_text("value = 1  # taut: ignore[TIME001]")
    assert main(["check", str(tmp_path)]) == 1
    assert "IGNORE001" in capsys.readouterr().out

    (tmp_path / "app" / "service.py").write_text("value = 1  # taut: ignore")
    assert main(["check", str(tmp_path)]) == 2
    assert "INVALID_INLINE_IGNORE" in capsys.readouterr().out


@pytest.mark.integration
@pytest.mark.parametrize(
    ("content", "role", "rule_id"),
    [
        ("import time\nasync def run():\n    time.sleep(1)", "service", "ASYNC001"),
        ("import os\nvalue = os.getenv('TOKEN')", "service", "SEC001"),
        ("import os\nvalue = os.environ['TOKEN']", "service", "SEC001"),
    ],
)
def test_new_safety_rules_block_known_calls(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    content: str,
    role: str,
    rule_id: str,
) -> None:
    _write_project(tmp_path, content, role=role)

    assert main(["check", str(tmp_path)]) == 1
    assert rule_id in capsys.readouterr().out


@pytest.mark.integration
def test_unknown_risky_call_is_advisory(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_project(tmp_path, "import requests\nrequests.custom_call()", role="adapter")

    assert main(["check", str(tmp_path)]) == 0
    assert "CAT001" in capsys.readouterr().out
