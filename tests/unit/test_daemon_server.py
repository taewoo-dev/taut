from __future__ import annotations

import socket
import struct
import threading
import time
from pathlib import Path

import pytest

from taut.daemon_protocol import (
    CheckWire,
    DaemonRequest,
    DaemonResponse,
    receive_response,
    send_request,
)
from taut.daemon_server import DaemonServer
from taut.daemon_state import DaemonStatus, read_status

_RunningServer = tuple[threading.Thread, DaemonStatus]


def _project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("TAUT_RUNTIME_DIR", str(tmp_path / "runtime"))
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
    return root


def _running_server(root: Path, monkeypatch: pytest.MonkeyPatch) -> _RunningServer:
    server = DaemonServer(root, idle_timeout=3)
    monkeypatch.setattr(server, "_install_signal_handlers", lambda: None)
    thread = threading.Thread(target=server.serve)
    thread.start()
    deadline = time.monotonic() + 2
    status = read_status(root)
    while status is None and time.monotonic() < deadline:
        time.sleep(0.01)
        status = read_status(root)
    assert status is not None
    return thread, status


def _roundtrip(status: DaemonStatus, request: DaemonRequest) -> DaemonResponse:
    with socket.create_connection(("127.0.0.1", status.port), timeout=2) as connection:
        send_request(connection, request)
        return receive_response(connection)


def test_in_process_server_ping_check_and_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _project(tmp_path, monkeypatch)
    thread, status = _running_server(root, monkeypatch)

    ping = _roundtrip(status, DaemonRequest("ping", status.token, str(root)))
    checked = _roundtrip(
        status,
        DaemonRequest("check", status.token, str(root), check=CheckWire(output_format="json")),
    )
    stopped = _roundtrip(status, DaemonRequest("stop", status.token, str(root)))
    thread.join(timeout=2)

    assert ping.ok and ping.exit_code == 0
    assert checked.ok and checked.stdout.startswith(b"{")
    assert checked.timings and checked.counters.reparsed_modules == 1
    assert stopped.ok
    assert not thread.is_alive()
    assert read_status(root) is None


def test_in_process_server_rejects_bad_requests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _project(tmp_path, monkeypatch)
    thread, status = _running_server(root, monkeypatch)

    denied = _roundtrip(status, DaemonRequest("ping", "bad" * 12, str(root)))
    unknown = _roundtrip(status, DaemonRequest("unknown", status.token, str(root)))
    invalid_check = _roundtrip(
        status,
        DaemonRequest("check", status.token, str(root), check=CheckWire(width=10)),
    )
    _roundtrip(status, DaemonRequest("stop", status.token, str(root)))
    thread.join(timeout=2)

    assert not denied.ok and "authentication" in (denied.error or "")
    assert not unknown.ok and "unknown daemon action" in (unknown.error or "")
    assert not invalid_check.ok and "rendering options" in (invalid_check.error or "")


def test_in_process_server_handles_malformed_frame_and_idle_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _project(tmp_path, monkeypatch)
    server = DaemonServer(root, idle_timeout=0.15)
    monkeypatch.setattr(server, "_install_signal_handlers", lambda: None)
    thread = threading.Thread(target=server.serve)
    thread.start()
    deadline = time.monotonic() + 2
    status = read_status(root)
    while status is None and time.monotonic() < deadline:
        time.sleep(0.01)
        status = read_status(root)
    assert status is not None

    with socket.create_connection(("127.0.0.1", status.port), timeout=2) as connection:
        connection.sendall(struct.pack(">I", 1) + b"x")
        response = receive_response(connection)
    thread.join(timeout=2)

    assert not response.ok
    assert not thread.is_alive()
    assert read_status(root) is None
