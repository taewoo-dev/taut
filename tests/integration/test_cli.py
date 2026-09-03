from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest
from tests.utils.config import assurance_toml

from taut.analysis.contracts import ModuleAnalysisResult, ResolverSettings, SourceInput
from taut.analysis.python.language_adapter import PythonAstAdapter
from taut.cli import main
from taut.configuration.assurance import BUILTIN_ASSURANCE_FEATURES


def _write_project(
    root: Path,
    content: str,
    *,
    role: str = "service",
    strict: bool = True,
) -> None:
    required = ("security",) if "os.getenv" in content or "os.environ" in content else ()
    app = root / "app"
    app.mkdir()
    (app / "service.py").write_text(content)
    policy_dir = root / ".policy"
    policy_dir.mkdir()
    (policy_dir / "policy.toml").write_text(
        f"""
schema_version = 5
strict = {str(strict).lower()}
packs = ["taut.backend"]
[project]
include = ["app/*.py"]
source_roots = ["."]
default_zone = "prod"
[[roles]]
name = "{role}"
patterns = ["app/*.py"]
[architecture.allow]
{role} = ["{role}"]
[assurance]
max_inline_ignores = {1 if "taut: ignore[" in content else 0}
{assurance_toml(required=required)}
""".strip()
    )


def _add_provider_list(root: Path, providers: tuple[str, ...]) -> None:
    path = root / ".policy" / "policy.toml"
    values = ", ".join(f'"{item}"' for item in providers)
    text = path.read_text()
    path.write_text(
        text.replace(
            'packs = ["taut.backend"]\n', f'packs = ["taut.backend"]\nproviders = [{values}]\n'
        )
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

{assurance_toml(pyproject=True)}
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
def test_cache_cli_flags_and_no_cache_do_not_write(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_project(tmp_path, "value = 1")
    with pytest.raises(SystemExit) as help_exit:
        main(["check", "--help"])
    assert help_exit.value.code == 0
    help_text = capsys.readouterr().out
    assert "--no-cache" in help_text and "--cache-dir" in help_text
    with pytest.raises(SystemExit):
        main(["cache", "--help"])
    assert "stats" in capsys.readouterr().out
    assert main(["check", str(tmp_path), "--no-cache"]) == 0
    capsys.readouterr()
    assert not (tmp_path / ".taut_cache").exists()


@pytest.mark.integration
def test_cache_stats_and_clean_commands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _write_project(tmp_path, "value = 1")
    assert main(["check", str(tmp_path)]) == 0
    capsys.readouterr()
    assert main(["cache", "stats", str(tmp_path)]) == 0
    stats = capsys.readouterr().out
    assert "모듈: 1" in stats
    assert "리포트: 1" in stats
    assert main(["cache", "clean", str(tmp_path)]) == 0
    assert "캐시 삭제 완료" in capsys.readouterr().out
    assert main(["cache", "stats", str(tmp_path)]) == 0
    assert "리포트: 0" in capsys.readouterr().out


@pytest.mark.integration
def test_cache_commands_follow_configured_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_project(tmp_path, "value = 1")
    config = tmp_path / ".policy" / "policy.toml"
    config.write_text(config.read_text() + '\n[cache]\ndirectory = "cache-data"\n')

    assert main(["check", str(tmp_path)]) == 0
    capsys.readouterr()
    assert (tmp_path / "cache-data").is_dir()
    assert not (tmp_path / ".taut_cache").exists()

    assert main(["cache", "stats", str(tmp_path)]) == 0
    assert "리포트: 1" in capsys.readouterr().out


@pytest.mark.integration
def test_cache_stats_does_not_create_an_absent_cache(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_project(tmp_path, "value = 1")

    assert main(["cache", "stats", str(tmp_path)]) == 0

    assert "리포트: 0" in capsys.readouterr().out
    assert not (tmp_path / ".taut_cache").exists()


@pytest.mark.integration
def test_report_miss_reuses_unchanged_module_analysis(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_project(tmp_path, "value = 1")
    (tmp_path / "app" / "other.py").write_text("other = 1\n")
    analyzed: list[int] = []
    original = PythonAstAdapter.analyze_modules

    def counting(
        self: PythonAstAdapter,
        sources: tuple[SourceInput, ...],
        resolver: ResolverSettings,
        workers: int,
    ) -> tuple[ModuleAnalysisResult, ...]:
        analyzed.append(len(sources))
        return original(self, sources, resolver, workers)

    monkeypatch.setattr(PythonAstAdapter, "analyze_modules", counting)
    assert main(["check", str(tmp_path)]) == 0
    capsys.readouterr()
    (tmp_path / "app" / "service.py").write_text("value = 2\n")

    assert main(["check", str(tmp_path)]) == 0
    cached_output = capsys.readouterr().out
    assert main(["check", str(tmp_path), "--no-cache"]) == 0
    fresh_output = capsys.readouterr().out

    assert analyzed == [2, 1, 2]
    assert cached_output == fresh_output


@pytest.mark.integration
def test_cli_json_v4_is_deterministic_for_compliant_project(
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
    assert payload["schema_version"] == 5
    coverage = cast(dict[str, object], payload["coverage"])
    analysis = cast(dict[str, object], coverage["analysis"])
    calls = cast(dict[str, int], analysis["calls"])
    assert calls["total"] >= 0
    assert payload["diagnostics"] == []
    assert len(cast(str, payload["decision_digest"])) == 64


@pytest.mark.integration
def test_workspace_check_keeps_member_graphs_isolated_and_aggregates_exit(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    backend = tmp_path / "backend"
    ai = tmp_path / "ai"
    backend.mkdir()
    ai.mkdir()
    _write_pyproject_project(backend, "value = 1\n", strict=True)
    _write_pyproject_project(
        ai,
        "from datetime import datetime\nvalue = datetime.now()\n",
        strict=True,
    )
    (tmp_path / "pyproject.toml").write_text(
        '[tool.taut.workspace]\nschema_version = 1\nmembers = ["backend", "ai"]\n'
    )

    code = main(["check", str(tmp_path), "--format", "json", "--no-cache"])
    payload = cast(dict[str, object], json.loads(capsys.readouterr().out))

    assert code == 1
    assert payload["kind"] == "workspace"
    members = cast(list[dict[str, object]], payload["members"])
    assert [member["path"] for member in members] == ["ai", "backend"]
    ai_report = cast(dict[str, object], members[0]["report"])
    backend_report = cast(dict[str, object], members[1]["report"])
    assert any(
        diagnostic["rule_id"] == "TIME001"
        for diagnostic in cast(list[dict[str, object]], ai_report["diagnostics"])
    )
    assert backend_report["diagnostics"] == []

    assert main(["check", str(tmp_path), "--no-cache"]) == 1
    text_output = capsys.readouterr().out
    assert "== ai ==" in text_output
    assert "== backend ==" in text_output
    assert "workspace 검사 완료" in text_output


@pytest.mark.integration
def test_workspace_member_configuration_failure_is_attributed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    member = tmp_path / "backend"
    member.mkdir()
    (member / "pyproject.toml").write_text('[project]\nname = "backend"\nversion = "1"\n')
    (tmp_path / "pyproject.toml").write_text('[tool.taut.workspace]\nmembers = ["backend"]\n')

    assert main(["check", str(tmp_path)]) == 2
    assert "workspace member backend" in capsys.readouterr().err


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
    assert "schema_version must be 5" in capsys.readouterr().err


@pytest.mark.integration
def test_cli_configuration_error_respects_json_format(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["check", str(tmp_path), "--format", "json"])
    payload = cast(dict[str, object], json.loads(capsys.readouterr().out))

    assert code == 2
    assert payload["schema_version"] == 5
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

    assert main(["config", "explain", str(tmp_path), "--format", "json"]) == 0
    config_explanation = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert config_explanation["schema_version"] == 5
    assert config_explanation["packs"] == ["taut.backend"]
    assert config_explanation["providers"] == [
        "taut.python-core",
        "taut.fastapi",
        "taut.pydantic",
        "taut.pytest",
        "taut.sqlalchemy",
        "taut.tortoise",
    ]


@pytest.mark.integration
def test_config_validate_loads_declared_plugins(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_project(tmp_path, "value = 1")
    _add_provider_list(tmp_path, ("missing.provider",))

    assert main(["config", "validate", str(tmp_path)]) == 2
    assert "unknown or ambiguous fact provider" in capsys.readouterr().err


@pytest.mark.integration
def test_default_backend_loads_all_builtin_providers_with_provenance(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_project(
        tmp_path,
        "from fastapi import APIRouter\nfrom pydantic import BaseModel\n"
        "class Item(BaseModel): value: int\nrouter = APIRouter()\n",
        strict=False,
    )

    assert main(["check", str(tmp_path), "--format", "json"]) in (0, 1)
    payload = cast(dict[str, object], json.loads(capsys.readouterr().out))
    coverage = cast(dict[str, object], payload["coverage"])
    analysis = cast(dict[str, object], coverage["analysis"])
    provenance = cast(list[dict[str, object]], analysis["capability_provenance"])
    providers = {item["provider"] for item in provenance}
    unavailable = cast(list[dict[str, object]], analysis["unavailable_capabilities"])
    assert {"taut.fastapi", "taut.pydantic", "taut.sqlalchemy"} <= providers
    assert unavailable == []


@pytest.mark.integration
def test_explicit_provider_list_remains_predictable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_project(tmp_path, "value = 1")
    _add_provider_list(tmp_path, ("taut.python-core",))

    assert main(["config", "explain", str(tmp_path), "--format", "json"]) == 0
    payload = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert payload["providers"] == ["taut.python-core"]


@pytest.mark.integration
def test_config_migrate_outputs_v5_without_modifying_source(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    policy_dir = tmp_path / ".policy"
    policy_dir.mkdir()
    source = policy_dir / "policy.toml"
    source.write_text("schema_version = 2\n[project]\ninclude = ['app/*.py']\nsource_roots = ['.']")
    original = source.read_text()

    assert main(["config", "migrate", str(tmp_path)]) == 0
    migrated = capsys.readouterr().out

    assert "schema_version = 5" in migrated
    assert "[assurance.features]" in migrated
    assert 'packs = ["taut.backend"]' in migrated
    assert (
        'providers = ["taut.python-core", "taut.fastapi", "taut.pydantic", '
        '"taut.pytest", "taut.sqlalchemy", "taut.tortoise"]' in migrated
    )
    assert source.read_text() == original


@pytest.mark.integration
def test_config_migrate_writes_only_to_explicit_new_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_project(tmp_path, "value = 1")
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname='sample'\nversion='0.1.0'\n\n[tool.taut]\nstrict=true\n")
    output = tmp_path / "migrated.toml"

    assert main(["config", "migrate", str(tmp_path), "--output", str(output)]) == 0
    assert capsys.readouterr().out == ""
    assert "schema_version = 5" in output.read_text()
    assert main(["config", "migrate", str(tmp_path), "--output", str(output)]) == 2
    assert "output already exists" in capsys.readouterr().err


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
    _write_project(
        tmp_path,
        "import requests\nrequests.custom_call()",
        role="adapter",
        strict=False,
    )

    assert main(["check", str(tmp_path)]) == 0
    assert "CAT001" in capsys.readouterr().out


@pytest.mark.integration
def test_init_json_is_read_only_then_writes_only_with_complete_answers(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "service.py").write_text("value = 1\n")

    assert main(["init", str(tmp_path), "--format", "json"]) == 2
    proposal = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert proposal["status"] == "needs_input"
    assert not (tmp_path / "pyproject.toml").exists()

    answers: dict[str, object] = {
        "schema_version": 6,
        "project_digest": proposal["project_digest"],
        "architecture": {"accept_safe_observed_edges": True, "risky_edges": []},
        "size": {"accept_observed": True},
        "features": {feature: "absent" for feature in BUILTIN_ASSURANCE_FEATURES},
    }
    answer_path = tmp_path / "answers.json"
    answer_path.write_text(json.dumps(answers))

    assert main(["init", str(tmp_path), "--answers", str(answer_path), "--write"]) == 0
    capsys.readouterr()
    assert "schema_version = 5" in (tmp_path / "pyproject.toml").read_text()
    assert main(["audit", str(tmp_path), "--format", "json"]) == 0
    audit = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert cast(dict[str, object], audit["assurance"])["complete"] is True


@pytest.mark.integration
def test_init_rejects_stale_answers_without_writing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "service.py").write_text("value = 1\n")
    answers = tmp_path / "answers.json"
    answers.write_text(
        json.dumps(
            {
                "schema_version": 6,
                "project_digest": "0" * 64,
                "architecture": {"accept_safe_observed_edges": True, "risky_edges": []},
                "size": {"accept_observed": True},
                "features": {feature: "absent" for feature in BUILTIN_ASSURANCE_FEATURES},
            }
        )
    )

    assert main(["init", str(tmp_path), "--answers", str(answers), "--write"]) == 2
    assert "stale" in capsys.readouterr().err
    assert not (tmp_path / "pyproject.toml").exists()


@pytest.mark.integration
def test_init_routes_existing_configuration_to_audit_or_migrate(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_project(tmp_path, "value = 1")

    assert main(["init", str(tmp_path), "--format", "json"]) == 2
    payload = cast(dict[str, object], json.loads(capsys.readouterr().out))
    issues = cast(list[dict[str, object]], payload["engine_issues"])
    assert "taut audit" in cast(str, issues[0]["message"])


@pytest.mark.integration
def test_init_guides_independent_projects_before_writing_workspace(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    for name in ("backend", "ai"):
        member = tmp_path / name
        member.mkdir()
        (member / "pyproject.toml").write_text(f'[project]\nname = "{name}"\nversion = "1"\n')
        (member / "app.py").write_text("value = 1\n")

    assert main(["init", str(tmp_path), "--format", "json"]) == 2
    payload = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert payload["status"] == "workspace_needs_members"
    assert payload["workspace"] == {
        "members": ["ai", "backend"],
        "unconfigured_members": ["ai", "backend"],
    }
    assert not (tmp_path / "pyproject.toml").exists()


@pytest.mark.integration
def test_init_writes_ready_workspace_and_root_config_validate_checks_members(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    for name in ("backend", "ai"):
        member = tmp_path / name
        member.mkdir()
        _write_pyproject_project(member, "value = 1\n", strict=True)

    assert main(["init", str(tmp_path), "--write"]) == 0
    output = capsys.readouterr().out
    assert "workspace 설정 저장 완료" in output
    assert 'members = ["ai", "backend"]' in (tmp_path / "pyproject.toml").read_text()

    assert main(["config", "validate", str(tmp_path)]) == 0
    validation = capsys.readouterr().out
    assert "ai/pyproject.toml" in validation
    assert "backend/pyproject.toml" in validation

    assert main(["config", "explain", str(tmp_path), "--format", "json"]) == 0
    explanation = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert explanation["workspace_schema_version"] == 1

    assert main(["config", "migrate", str(tmp_path)]) == 2
    assert "migrate workspace members individually" in capsys.readouterr().err

    assert main(["audit", str(tmp_path), "--format", "json"]) == 0
    payload = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert payload["kind"] == "workspace_audit"

    assert main(["audit", str(tmp_path)]) == 0
    assert "workspace assurance 완료" in capsys.readouterr().out


@pytest.mark.integration
def test_audit_reports_python_source_outside_configured_scope(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_project(tmp_path, "value = 1")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_service.py").write_text("def test_value(): pass\n")

    assert main(["audit", str(tmp_path), "--format", "json"]) == 2
    payload = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert payload["assurance"] is not None, [
        item["message"] for item in cast(list[dict[str, object]], payload["engine_issues"])
    ]
    assurance = cast(dict[str, object], payload["assurance"])
    issues = cast(list[dict[str, object]], assurance["issues"])
    assert {issue["code"] for issue in issues} >= {"SOURCE_UNACCOUNTED"}


@pytest.mark.integration
def test_audit_requires_semantic_provider_for_imported_tortoise(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_project(
        tmp_path,
        "from tortoise.models import Model\nclass User(Model): pass\n",
        role="model",
    )
    _add_provider_list(tmp_path, ("taut.python-core",))

    assert main(["audit", str(tmp_path), "--format", "json"]) == 2
    payload = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assurance = cast(dict[str, object], payload["assurance"])
    issues = cast(list[dict[str, object]], assurance["issues"])
    assert any(
        issue["code"] == "FRAMEWORK_PROVIDER_MISSING" and issue["subject"] == "tortoise"
        for issue in issues
    )


@pytest.mark.integration
def test_machine_readable_schema_and_rules_are_discoverable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["config", "schema", "--format", "json"]) == 0
    schema = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert schema["schema_version"] == 5

    assert main(["rules", "DTO001", "--format", "json"]) == 0
    rule = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert rule["id"] == "DTO001" and rule["target"] == "module"


@pytest.mark.integration
def test_init_requires_backend_policy_details_and_writes_active_setup(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    files = {
        "app/router.py": """
from fastapi import APIRouter
router = APIRouter()
@router.get('/items')
def items(): return []
""",
        "app/schema.py": """
from pydantic import BaseModel, ConfigDict
REQUEST_CONFIG = ConfigDict(extra='forbid')
class Item(BaseModel):
    value: str
""",
        "app/snapshot.py": """
from pydantic import BaseModel
class ItemSnapshot(BaseModel):
    value: str
""",
        "app/dto.py": """
from dataclasses import dataclass
@dataclass(frozen=True)
class ItemResult:
    value: str
""",
        "app/errors.py": """
from enum import StrEnum
class ErrorCode(StrEnum):
    BAD = 'BAD'
class AppError(Exception):
    pass
""",
        "app/model.py": (
            "from sqlalchemy.orm import DeclarativeBase\nclass Base(DeclarativeBase): pass\n"
        ),
        "app/service.py": """
import os
import httpx
from contextlib import asynccontextmanager
@asynccontextmanager
async def transaction():
    yield object()
@asynccontextmanager
async def logged_call():
    yield
async def run(session):
    async with transaction():
        await session.commit()
    async with logged_call():
        await httpx.get('https://example.invalid')
    return os.getenv('TOKEN')
""",
        "tests/test_item.py": "def test_item(): pass\n",
        "migrations/revision.py": "revision = '1'\n",
        "scripts/repair.py": "def main(): pass\n",
    }
    for relative, content in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content.strip() + "\n")

    assert main(["init", str(tmp_path), "--format", "json"]) == 2
    proposal = cast(dict[str, object], json.loads(capsys.readouterr().out))
    discovered = cast(dict[str, object], proposal["discovered"])
    detected = set(cast(list[str], discovered["features"]))
    assert detected == set(BUILTIN_ASSURANCE_FEATURES)

    answers: dict[str, object] = {
        "schema_version": 6,
        "project_digest": proposal["project_digest"],
        "architecture": {"accept_safe_observed_edges": True, "risky_edges": []},
        "size": {"accept_observed": True},
        "roles": {"app/snapshot.py": "snapshot"},
        "features": {feature: "required" for feature in BUILTIN_ASSURANCE_FEATURES},
        "policy": {
            "code_conventions": {
                "request_config_symbols": ["app.schema.REQUEST_CONFIG"],
                "exception_base_symbols": ["app.errors.AppError"],
                "error_code_enum_symbols": ["app.errors.ErrorCode"],
            },
            "enum": {"shared_modules": ["app.errors"]},
            "transaction": {
                "owner_roles": ["service"],
                "session_providers": ["app.service.transaction"],
            },
            "external": {
                "logged_calls": ["httpx.get"],
                "wrappers": ["app.service.logged_call"],
            },
        },
    }
    answer_path = tmp_path / "answers.json"
    answer_path.write_text(json.dumps(answers))
    assert main(["init", str(tmp_path), "--answers", str(answer_path), "--write"]) == 0
    capsys.readouterr()

    assert main(["audit", str(tmp_path), "--format", "json"]) == 0
    payload = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assurance = cast(dict[str, object], payload["assurance"])
    features = cast(list[dict[str, object]], assurance["features"])
    missing = [item["name"] for item in features if item["detected"] is not True]
    assert not missing
    assert cast(list[dict[str, object]], assurance["issues"]) == []


@pytest.mark.integration
def test_audit_rejects_stale_selectors_exceptions_and_exception_budget(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_project(
        tmp_path,
        "from datetime import datetime\nvalue = datetime.now()  # taut: ignore[TIME001]",
    )
    config = tmp_path / ".policy" / "policy.toml"
    text = config.read_text().replace("max_inline_ignores = 1", "max_inline_ignores = 0")
    text = text.replace('service = ["service"]', 'service = ["service"]\nghost = ["ghost"]')
    config.write_text(
        text
        + """

[[roles]]
name = "ghost"
patterns = ["missing/*.py"]

[[zones]]
name = "test"
patterns = ["missing/*.py"]

[[exclusions]]
patterns = ["generated/*.py"]
reason = "generated elsewhere"

[[assurance.assertions]]
domain = "dto"
kind = "path"
target = "missing.py"
state = "not_applicable"
reason = "legacy generator"
"""
    )

    assert main(["audit", str(tmp_path), "--format", "json"]) == 2
    payload = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert payload["assurance"] is not None, [
        item["message"] for item in cast(list[dict[str, object]], payload["engine_issues"])
    ]
    assurance = cast(dict[str, object], payload["assurance"])
    issues = cast(list[dict[str, object]], assurance["issues"])
    assert {item["code"] for item in issues} >= {
        "IGNORE_BUDGET_EXCEEDED",
        "ASSERTION_UNUSED",
        "EXCLUSION_UNUSED",
        "ROLE_SELECTOR_UNUSED",
        "ZONE_SELECTOR_UNUSED",
    }
