from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.utils.builders import analyze, make_context, make_source
from tests.utils.config import assurance_toml

from taut.check_service import CheckRequest, ResidentCheckSession, run_check_request
from taut.domain.ids import RuleId
from taut.loading.config_loader import load_project_configuration
from taut.loading.config_simplification import simplify_configuration
from taut.policy.engine import PolicyEngine
from taut.policy.rules import builtin_rule_registry
from taut.reporting.text import render_text


def _project(root: Path, source: str) -> CheckRequest:
    (root / "app").mkdir()
    (root / "app/service.py").write_text(source)
    (root / "pyproject.toml").write_text(
        '[tool.taut]\nschema_version = 5\nproviders = ["taut.python-core"]\n'
        'source_roots = ["."]\n[tool.taut.roles]\nservice = ["app/*.py"]\n'
        '[tool.taut.allow]\nservice = ["service"]\n' + assurance_toml(pyproject=True)
    )
    return CheckRequest(root, output_format="json")


@pytest.mark.parametrize(
    "source",
    [
        "import time\nasync def work():\n    time.sleep(1)\n",
        'from pathlib import Path\nasync def work():\n    Path("data").read_text()\n',
        'from pathlib import Path as P\nasync def work():\n    P("data").read_bytes()\n',
        "from pathlib import Path\nasync def work():\n"
        '    p = Path("data")\n    p.write_text("x")\n',
        'async def work():\n    open("data")\n',
    ],
)
def test_known_blocking_calls_fail_strict_check(tmp_path: Path, source: str) -> None:
    result = run_check_request(_project(tmp_path, source))
    assert result.exit_code == 1
    assert any(finding.rule_id == RuleId("ASYNC001") for finding in result.findings)


@pytest.mark.parametrize("owner", ["requests.Session", "requests.sessions.Session"])
def test_session_methods_have_blocking_effects(owner: str) -> None:
    snapshot = analyze(
        make_source(
            "app/service.py", f'import requests\nasync def work():\n    {owner}().get("url")\n'
        )
    )
    context = make_context(snapshot, roles={"service": ("app/*.py",)})
    result = PolicyEngine(builtin_rule_registry()).run(context)
    assert any(finding.rule_id == RuleId("ASYNC001") for finding in result.findings)


@pytest.mark.parametrize(
    ("helper", "call"),
    [
        ("def invoke(fn):\n    fn(1)", "invoke(time.sleep)"),
        ("def invoke(fn):\n    fn(1)", "invoke(fn=time.sleep)"),
        ("def invoke(*, fn):\n    fn(1)", "invoke(fn=time.sleep)"),
        ("def invoke(fn, /):\n    fn(1)", "invoke(time.sleep)"),
        ("def invoke(fn=time.sleep):\n    fn(1)", "invoke()"),
        ("def invoke(fn):\n    fn(1)\ndef helper():\n    invoke(time.sleep)", "helper()"),
    ],
)
def test_callback_execution_is_not_silently_safe(tmp_path: Path, helper: str, call: str) -> None:
    result = run_check_request(
        _project(tmp_path, f"import time\n{helper}\nasync def work():\n    {call}\n")
    )
    assert result.exit_code == 2
    assert result.report is not None
    assert any(
        issue.rule_id == RuleId("ASYNC001") and issue.reason.code == "callback_effect"
        for issue in result.report.coverage.skipped
    )
    payload = json.loads(result.stdout)
    assert payload["interpretation"]["runtime_safety_proven"] is False


@pytest.mark.parametrize(
    "source",
    [
        "import time\ndef store(fn):\n    return fn\nasync def work():\n    store(time.sleep)\n",
        "import asyncio\nimport time\nasync def work():\n"
        "    await asyncio.to_thread(time.sleep, 1)\n",
        "def invoke(fn):\n    fn(1)\nasync def work():\n    invoke(str)\n",
        'def Path(value):\n    return value\nasync def work():\n    Path("data").read_text()\n',
        'def open(value):\n    return value\nasync def work():\n    open("data")\n',
        "import time\ndef invoke(fn):\n    fn = str\n    fn(1)\n"
        "async def work():\n    invoke(time.sleep)\n",
    ],
)
def test_callable_storage_offloading_and_shadowing_are_not_blocked(
    tmp_path: Path, source: str
) -> None:
    result = run_check_request(_project(tmp_path, source))
    assert result.exit_code == 0


def test_callback_body_changes_preserve_resident_cold_parity(tmp_path: Path) -> None:
    request = _project(
        tmp_path,
        "import time\nfrom app.helper import invoke\nasync def work():\n    invoke(time.sleep)\n",
    )
    helper = tmp_path / "app/helper.py"
    session = ResidentCheckSession(tmp_path)
    for body, expected in [("return fn", 0), ("fn(1)", 2), ("return fn", 0)]:
        helper.write_text(f"def invoke(fn):\n    {body}\n")
        resident = session.check(request)
        cold = run_check_request(request)
        assert resident.exit_code == cold.exit_code == expected
        assert resident.stdout == cold.stdout
        assert resident.stderr == cold.stderr


def test_uncertainty_does_not_hide_a_known_blocking_helper(tmp_path: Path) -> None:
    request = _project(
        tmp_path,
        "import time\ndef invoke(fn):\n    fn(1)\n"
        "def helper():\n    time.sleep(1)\n    invoke(time.sleep)\n"
        "async def work():\n    helper()\n",
    )
    result = run_check_request(request)
    assert any(finding.rule_id == RuleId("ASYNC001") for finding in result.findings)


def test_staged_rule_remains_visible_and_can_be_promoted(tmp_path: Path) -> None:
    request = _project(tmp_path, "import time\nasync def work():\n    time.sleep(1)\n")
    path = tmp_path / "pyproject.toml"
    base = path.read_text()
    path.write_text(base + '\n[tool.taut.rules]\nASYNC001 = "advisory"\n')
    session = ResidentCheckSession(tmp_path)
    advisory = session.check(request)
    payload = json.loads(advisory.stdout)
    assert advisory.exit_code == 0
    assert payload["coverage"]["rule_levels"]["ASYNC001"] == "advisory"
    assert any(item["rule_id"] == "ASYNC001" for item in payload["diagnostics"])
    original = load_project_configuration(tmp_path)
    path.write_text(simplify_configuration(tmp_path, None, original))
    assert load_project_configuration(tmp_path).policy.rules == original.policy.rules
    path.write_text(base)
    enforced = session.check(request)
    assert enforced.exit_code == 1
    assert enforced.stdout == run_check_request(request).stdout


def test_staging_does_not_bypass_assurance(tmp_path: Path) -> None:
    request = _project(tmp_path, "import time\nasync def work():\n    time.sleep(1)\n")
    path = tmp_path / "pyproject.toml"
    path.write_text(
        path.read_text().replace('api = "absent"', 'api = "required"')
        + '\n[tool.taut.rules]\nASYNC001 = "advisory"\n'
    )
    result = run_check_request(request)
    assert result.exit_code == 2
    assert result.report is not None and result.report.assurance.issues
    text = render_text(result.report, color=True)
    assert "지원 범위 내 정책 위반 없음" not in text
    assert "\033[31m검사 완료:" in text
