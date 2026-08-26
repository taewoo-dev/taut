from __future__ import annotations

import os
import signal
import socket
import stat
import time
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from pathlib import Path

import pytest

from taut.check_service import CheckRequest, CheckResult, run_check_request
from taut.cli import main
from taut.daemon_client import (
    DaemonError,
    check_daemon,
    daemon_status,
    restart_daemon,
    start_daemon,
    stop_daemon,
)
from taut.daemon_protocol import (
    PROTOCOL_VERSION,
    STATUS_SCHEMA_VERSION,
    DaemonRequest,
    receive_response,
    send_request,
)
from taut.daemon_state import (
    DaemonStatus,
    read_status,
    runtime_directory,
    status_path,
    write_status,
)
from taut.policy.packs import plugin_environment_digest


@pytest.fixture
def daemon_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Generator[tuple[Path, CheckRequest], None, None]:
    runtime = tmp_path / "runtime"
    monkeypatch.setenv("TAUT_RUNTIME_DIR", str(runtime))
    root = tmp_path / "project"
    (root / "app").mkdir(parents=True)
    (root / "app" / "service.py").write_text("value = 1\n")
    (root / ".policy").mkdir()
    (root / ".policy" / "policy.toml").write_text(
        """
schema_version = 3
packs = ["taut.backend"]
providers = ["taut.python-core"]
[project]
include = ["app/*.py"]
source_roots = ["."]
default_zone = "prod"
[[roles]]
name = "service"
patterns = ["app/*.py"]
[architecture.allow]
service = ["service"]
""".strip()
    )
    request = CheckRequest(root)
    yield root, request
    try:
        stop_daemon(root, timeout=2)
    except DaemonError:
        status = read_status(root)
        if status is not None:
            _kill_test_daemon(status.pid)


@pytest.mark.integration
def test_status_file_is_strict_atomic_and_user_only(
    daemon_project: tuple[Path, CheckRequest],
) -> None:
    root, _ = daemon_project
    status = _fake_status(root)
    write_status(root, status)

    assert read_status(root) == status
    assert stat.S_IMODE(status_path(root).stat().st_mode) == 0o600
    assert stat.S_IMODE(runtime_directory(root).stat().st_mode) == 0o700
    status_path(root).write_bytes(b"not-json")
    assert read_status(root) is None


@pytest.mark.integration
def test_daemon_lifecycle_and_exact_local_parity(daemon_project: tuple[Path, CheckRequest]) -> None:
    root, request = daemon_project
    local = run_check_request(request)

    started = start_daemon(root)
    first = check_daemon(request)
    second = check_daemon(request)

    assert daemon_status(root) is not None
    assert first.stdout == second.stdout == local.stdout
    assert first.stderr == second.stderr == local.stderr
    assert first.exit_code == second.exit_code == local.exit_code
    assert second.counters.reparsed_modules == 0
    assert second.counters.recomputed_evaluations == 0
    assert stop_daemon(root)
    assert daemon_status(root) is None
    assert started.instance_id


@pytest.mark.integration
def test_restart_replaces_the_verified_instance(daemon_project: tuple[Path, CheckRequest]) -> None:
    root, _ = daemon_project
    first = start_daemon(root)

    second = restart_daemon(root)

    assert second.instance_id != first.instance_id
    assert second.pid != first.pid


@pytest.mark.integration
def test_server_rejects_auth_root_and_version_mismatch(
    daemon_project: tuple[Path, CheckRequest],
) -> None:
    root, _ = daemon_project
    status = start_daemon(root)
    requests = (
        DaemonRequest("ping", "wrong" * 10, str(root)),
        DaemonRequest("ping", status.token, str(root / "other")),
        DaemonRequest("ping", status.token, str(root), taut_version="0.0.invalid"),
    )

    for request in requests:
        with socket.create_connection(("127.0.0.1", status.port), timeout=2) as connection:
            send_request(connection, request)
            response = receive_response(connection)
        assert not response.ok
        assert response.error


@pytest.mark.integration
def test_two_startup_racers_observe_one_instance(daemon_project: tuple[Path, CheckRequest]) -> None:
    root, _ = daemon_project

    def start(_: int) -> DaemonStatus:
        return start_daemon(root)

    with ThreadPoolExecutor(max_workers=4) as executor:
        statuses = tuple(executor.map(start, range(4)))

    assert len({item.instance_id for item in statuses}) == 1
    assert len({item.pid for item in statuses}) == 1


@pytest.mark.integration
def test_concurrent_clients_are_serialized_with_deterministic_output(
    daemon_project: tuple[Path, CheckRequest],
) -> None:
    _, request = daemon_project
    check_daemon(request)

    def check(_: int) -> CheckResult:
        return check_daemon(request)

    with ThreadPoolExecutor(max_workers=6) as executor:
        results = tuple(executor.map(check, range(6)))

    assert len({item.stdout for item in results}) == 1
    assert all(item.counters.reparsed_modules == 0 for item in results)


@pytest.mark.integration
def test_crashed_daemon_is_recovered_once(daemon_project: tuple[Path, CheckRequest]) -> None:
    root, request = daemon_project
    crashed = start_daemon(root)
    _kill_test_daemon(crashed.pid)

    recovered = check_daemon(request)
    current = daemon_status(root)

    assert recovered.stdout
    assert current is not None
    assert current.instance_id != crashed.instance_id


@pytest.mark.integration
def test_idle_daemon_exits_and_cleans_its_status(daemon_project: tuple[Path, CheckRequest]) -> None:
    root, _ = daemon_project
    status = start_daemon(root, idle_timeout=0.2)

    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and read_status(root) is not None:
        time.sleep(0.05)

    assert read_status(root) is None
    _reap(status.pid)


@pytest.mark.integration
def test_stale_status_is_replaced_without_signaling_its_pid(
    daemon_project: tuple[Path, CheckRequest],
) -> None:
    root, _ = daemon_project
    stale = _fake_status(root, pid=os.getpid(), port=9, token="z" * 43)
    write_status(root, stale)

    running = start_daemon(root)

    assert running.instance_id != stale.instance_id
    assert running.pid != os.getpid()


@pytest.mark.integration
def test_cli_daemon_commands_cover_start_status_and_stop(
    daemon_project: tuple[Path, CheckRequest], capsys: pytest.CaptureFixture[str]
) -> None:
    root, _ = daemon_project
    assert main(["daemon", "start", str(root)]) == 0
    assert "running" in capsys.readouterr().out
    assert main(["daemon", "status", str(root)]) == 0
    assert "running" in capsys.readouterr().out
    assert main(["daemon", "stop", str(root)]) == 0
    assert "stopped" in capsys.readouterr().out


@pytest.mark.integration
def test_cli_auto_falls_back_but_required_fails_clearly(
    daemon_project: tuple[Path, CheckRequest],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _ = daemon_project

    def unavailable(_: CheckRequest) -> object:
        raise DaemonError("unavailable for test")

    monkeypatch.setattr("taut.cli.check_daemon", unavailable)
    assert main(["check", str(root), "--daemon", "auto", "--no-cache"]) == 0
    assert "문제 없음" in capsys.readouterr().out
    assert main(["check", str(root), "--daemon", "required", "--no-cache"]) == 2
    assert "unavailable for test" in capsys.readouterr().err


def _fake_status(
    root: Path,
    *,
    pid: int = 999_999,
    port: int = 65_000,
    token: str = "x" * 43,
) -> DaemonStatus:
    return DaemonStatus(
        STATUS_SCHEMA_VERSION,
        PROTOCOL_VERSION,
        "0.2.0",
        plugin_environment_digest(),
        str(root.resolve()),
        pid,
        None,
        "fake-instance",
        port,
        token,
        1.0,
        1.0,
    )


def _kill_test_daemon(pid: int) -> None:
    os.kill(pid, signal.SIGKILL)
    _reap(pid)


def _reap(pid: int) -> None:
    with suppress(ChildProcessError, OSError):
        os.waitpid(pid, 0)
