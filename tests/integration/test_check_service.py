from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from tests.utils.config import assurance_toml

from taut.analysis.providers import CapabilitySpec
from taut.check_service import CheckRequest, CheckResult, ResidentCheckSession, run_check_request
from taut.cli import main
from taut.domain.evaluations import ChangeImpact, RuleTarget, RuleTargetRef, RuleVerdict
from taut.domain.facts import AnalysisStage
from taut.domain.frozen import FrozenMap
from taut.domain.ids import RuleId
from taut.policy.context import PolicyContext
from taut.policy.packs import RulePackV1
from taut.policy.registry import RuleRegistry
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements

_PROVIDERS = (
    "taut.python-core",
    "taut.fastapi",
    "taut.pydantic",
    "taut.sqlalchemy",
)


@dataclass(frozen=True)
class _PassingRule:
    id: RuleId

    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        del context
        return RuleEvaluation(self.id, target, RuleVerdict.PASS, ())


@dataclass(frozen=True)
class _EntryPoint:
    name: str
    value: str
    factory: Callable[[], object]

    def load(self) -> Callable[[], object]:
        return self.factory


def _write_config(root: Path, *, providers: tuple[str, ...] = _PROVIDERS, limit: int = 500) -> None:
    values = ", ".join(f'"{item}"' for item in providers)
    (root / ".policy").mkdir(exist_ok=True)
    (root / ".policy" / "policy.toml").write_text(
        f"""
schema_version = 5
packs = ["taut.backend"]
providers = [{values}]
[project]
include = ["app/*.py"]
source_roots = ["."]
default_zone = "prod"
[[roles]]
name = "service"
patterns = ["app/*.py"]
[architecture.allow]
service = ["service"]
[size]
default_max_lines = {limit}
{assurance_toml()}
""".strip()
    )


def _project(root: Path, files: dict[str, str] | None = None) -> CheckRequest:
    app = root / "app"
    app.mkdir()
    for name, content in (files or {"service.py": "value = 1\n"}).items():
        (app / name).write_text(content)
    _write_config(root)
    return CheckRequest(root)


def _assert_fresh_parity(request: CheckRequest, result: CheckResult) -> None:
    fresh = run_check_request(request)
    assert result.stdout == fresh.stdout
    assert result.exit_code == fresh.exit_code
    assert result.report == fresh.report


@pytest.mark.integration
def test_external_rule_pack_can_define_and_run_a_custom_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    custom_id = RuleId("CUSTOM001")
    definition = RuleDefinition(
        id=custom_id,
        behavior_version=1,
        title="Custom passing rule",
        help="Used to verify the public extension runtime.",
        target=RuleTarget.PROJECT,
        requirements=RuleRequirements(frozenset(), AnalysisStage.DISCOVERED, False, False),
        change_impact=ChangeImpact.PROJECT,
        implementation=_PassingRule(custom_id),
        compliant_fixtures=("value = 1",),
        violation_fixtures=("value = 0",),
    )
    pack = RulePackV1("example.pack", "1.0.0", RuleRegistry.build((definition,)))
    point = _EntryPoint("example.pack", "example:pack", lambda: pack)
    monkeypatch.setattr("taut.policy.packs.entry_points", lambda: (point,))

    app = tmp_path / "app"
    app.mkdir()
    (app / "service.py").write_text("value = 1\n")
    (tmp_path / ".policy").mkdir()
    config_path = tmp_path / ".policy" / "policy.toml"
    config_path.write_text(
        f"""
schema_version = 5
strict = false
packs = ["example.pack"]
providers = []
[project]
include = ["app/*.py"]
source_roots = ["."]
default_zone = "prod"
[[roles]]
name = "service"
patterns = ["app/*.py"]
[architecture.allow]
service = ["service"]
[rules]
CUSTOM001 = "enforced"
{assurance_toml()}
""".strip()
    )

    strict_text = config_path.read_text().replace("strict = false", "strict = true")
    config_path.write_text(strict_text)
    with pytest.raises(ValueError, match="does not provide an assurance auditor"):
        run_check_request(CheckRequest(tmp_path))
    config_path.write_text(strict_text.replace("strict = true", "strict = false"))

    result = run_check_request(CheckRequest(tmp_path))

    assert result.exit_code == 0
    assert result.report is not None
    assert result.report.coverage.enabled_rules == 1
    assert result.report.coverage.passed == 1


@pytest.mark.integration
def test_single_shot_cli_delegates_with_exact_bytes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    request = _project(tmp_path)
    direct = run_check_request(request)

    assert main(["check", str(tmp_path), "--no-cache"]) == direct.exit_code
    captured = capsys.readouterr()
    assert captured.out.encode() == direct.stdout
    assert captured.err.encode() == direct.stderr


@pytest.mark.integration
def test_unchanged_resident_run_reuses_every_layer(tmp_path: Path) -> None:
    request = _project(tmp_path)
    session = ResidentCheckSession(tmp_path)
    first = session.check(request)
    second = session.check(request)

    assert second.stdout == first.stdout
    assert second.counters.reparsed_modules == 0
    assert second.counters.reused_modules == 1
    assert second.counters.recomputed_providers == 0
    assert second.counters.reused_providers == len(_PROVIDERS)
    assert second.counters.recomputed_evaluations == 0
    assert second.counters.reused_evaluations > 0
    assert not second.counters.full_policy_rerun


@pytest.mark.integration
def test_ordinary_edit_matches_fresh_full_run(tmp_path: Path) -> None:
    request = _project(tmp_path)
    session = ResidentCheckSession(tmp_path)
    session.check(request)
    (tmp_path / "app" / "service.py").write_text(
        "from datetime import datetime\nvalue = datetime.now()\n"
    )

    changed = session.check(request)

    assert changed.counters.reparsed_modules == 1
    assert changed.counters.recomputed_providers == len(_PROVIDERS)
    _assert_fresh_parity(request, changed)


@pytest.mark.integration
def test_shared_import_edit_matches_fresh_full_run(tmp_path: Path) -> None:
    request = _project(
        tmp_path,
        {"base.py": "value = 1\n", "consumer.py": "from app.base import value\nresult = value\n"},
    )
    session = ResidentCheckSession(tmp_path)
    session.check(request)
    (tmp_path / "app" / "base.py").write_text("value = 2\n")

    changed = session.check(request)

    assert changed.counters.reparsed_modules == 1
    assert changed.counters.reused_modules == 1
    _assert_fresh_parity(request, changed)


@pytest.mark.integration
def test_added_source_matches_fresh_full_run(tmp_path: Path) -> None:
    request = _project(tmp_path)
    session = ResidentCheckSession(tmp_path)
    session.check(request)
    (tmp_path / "app" / "other.py").write_text("other = 2\n")

    changed = session.check(request)

    assert changed.counters.reparsed_modules == 1
    _assert_fresh_parity(request, changed)


@pytest.mark.integration
def test_removed_source_matches_fresh_full_run(tmp_path: Path) -> None:
    request = _project(tmp_path, {"service.py": "value = 1\n", "other.py": "other = 2\n"})
    session = ResidentCheckSession(tmp_path)
    session.check(request)
    (tmp_path / "app" / "other.py").unlink()

    changed = session.check(request)

    assert changed.counters.reparsed_modules == 0
    assert changed.counters.reused_modules == 1
    _assert_fresh_parity(request, changed)


@pytest.mark.integration
def test_syntax_failure_and_recovery_match_fresh_runs(tmp_path: Path) -> None:
    request = _project(tmp_path)
    session = ResidentCheckSession(tmp_path)
    session.check(request)
    source = tmp_path / "app" / "service.py"
    source.write_text("def broken(:\n")
    broken = session.check(request)
    _assert_fresh_parity(request, broken)
    source.write_text("value = 1\n")

    recovered = session.check(request)

    assert recovered.counters.reparsed_modules == 1
    _assert_fresh_parity(request, recovered)


@pytest.mark.integration
def test_configuration_change_resets_all_runtime_state(tmp_path: Path) -> None:
    request = _project(tmp_path)
    session = ResidentCheckSession(tmp_path)
    session.check(request)
    _write_config(tmp_path, limit=1)

    reset_result = session.check(request)

    assert reset_result.counters.reparsed_modules == 1
    assert reset_result.counters.recomputed_providers == len(_PROVIDERS)
    assert reset_result.counters.full_policy_rerun
    _assert_fresh_parity(request, reset_result)


@pytest.mark.integration
def test_seeded_mixed_edit_sequence_matches_fresh_and_releases_old_revisions(
    tmp_path: Path,
) -> None:
    request = _project(
        tmp_path,
        {
            "service.py": "def value() -> int:\n    return 1\n",
            "obsolete.py": "obsolete = True\n",
            "rename_me.py": "renamed = False\n",
        },
    )
    session = ResidentCheckSession(tmp_path)
    session.check(request)

    operations: list[Callable[[], object]] = [
        lambda: (tmp_path / "app" / "service.py").write_text("def value() -> int:\n    return 2\n"),
        lambda: (tmp_path / "app" / "service.py").write_text(
            "def value(seed: int = 2) -> int:\n    return seed\n"
        ),
        lambda: (tmp_path / "app" / "service.py").write_text("def broken(:\n"),
        lambda: (tmp_path / "app" / "added.py").write_text("added = True\n"),
        lambda: (tmp_path / "app" / "obsolete.py").unlink(),
        lambda: (tmp_path / "app" / "rename_me.py").rename(tmp_path / "app" / "renamed.py"),
        lambda: _write_config(tmp_path, limit=250),
    ]
    random.Random(20260905).shuffle(operations)

    for operation in operations:
        operation()

        changed = session.check(request)

        _assert_fresh_parity(request, changed)
        assert session.retained_revision_count == 1


@pytest.mark.integration
def test_render_options_change_without_reanalysis(tmp_path: Path) -> None:
    request = _project(tmp_path)
    session = ResidentCheckSession(tmp_path)
    text_result = session.check(request)

    json_result = session.check(replace(request, output_format="json", width=60))

    assert json_result.stdout != text_result.stdout
    assert json_result.counters.reparsed_modules == 0
    assert json_result.counters.recomputed_providers == 0
    assert json_result.counters.recomputed_evaluations == 0


@pytest.mark.integration
def test_resident_session_rejects_another_root(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    request = _project(first)
    other = _project(second)
    session = ResidentCheckSession(first)
    session.check(request)

    with pytest.raises(ValueError, match="project root"):
        session.check(other)


@pytest.mark.integration
def test_provider_exception_is_a_deterministic_coverage_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _project(tmp_path)
    _write_config(tmp_path, providers=("broken",))

    class BrokenProvider:
        id = "broken"
        version = "1.0.0"
        provides = frozenset({CapabilitySpec("broken.facts@1")})

        def analyze(self, snapshot: object) -> FrozenMap[str, tuple[object, ...]]:
            raise RuntimeError("provider exploded")

    def load_broken(_: str) -> BrokenProvider:
        return BrokenProvider()

    monkeypatch.setattr("taut.check_runtime.load_fact_provider", load_broken)
    session = ResidentCheckSession(tmp_path)

    first = session.check(request)
    second = session.check(request)

    assert first.exit_code == second.exit_code == 2
    assert first.stdout == second.stdout
    assert first.report is not None
    assert first.report.analysis_coverage.unavailable_capabilities[0].name == "broken.facts@1"


@pytest.mark.integration
def test_repeated_resident_output_is_deterministic(tmp_path: Path) -> None:
    request = _project(tmp_path)
    session = ResidentCheckSession(tmp_path)

    outputs = {session.check(request).stdout for _ in range(4)}

    assert len(outputs) == 1


@pytest.mark.integration
def test_reset_rebuilds_state_and_close_is_terminal(tmp_path: Path) -> None:
    request = _project(tmp_path)
    session = ResidentCheckSession(tmp_path)
    assert session.retained_revision_count == 0
    session.check(request)
    assert session.retained_revision_count == 1
    session.reset()
    assert session.retained_revision_count == 0

    rebuilt = session.check(request)

    assert rebuilt.counters.reparsed_modules == 1
    assert rebuilt.counters.full_policy_rerun
    session.close()
    with pytest.raises(RuntimeError, match="closed"):
        session.check(request)
