# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false
from __future__ import annotations

import socket
from contextlib import nullcontext
from pathlib import Path

import pytest

import taut.daemon_client as client
from taut import __version__
from taut.check_service import CheckRequest
from taut.daemon_protocol import PROTOCOL_VERSION, STATUS_SCHEMA_VERSION, DaemonResponse
from taut.daemon_state import DaemonStatus
from taut.policy.packs import plugin_environment_digest


def _status(root: Path, *, instance: str = "one") -> DaemonStatus:
    return DaemonStatus(
        STATUS_SCHEMA_VERSION,
        PROTOCOL_VERSION,
        __version__,
        plugin_environment_digest(),
        str(root.resolve()),
        123,
        None,
        instance,
        12345,
        "x" * 43,
        1.0,
        1.0,
    )


def test_start_reports_child_exit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class ExitedProcess:
        pid = 123

        def poll(self) -> int:
            return 7

    monkeypatch.setattr(client, "startup_lock", lambda *_args, **_kwargs: nullcontext())
    monkeypatch.setattr(client, "read_status", lambda _: None)
    monkeypatch.setattr(client, "remove_unusable_status", lambda *_: None)
    monkeypatch.setattr(client, "_spawn", lambda *_: ExitedProcess())

    with pytest.raises(client.DaemonError, match="exited during startup"):
        client.start_daemon(tmp_path, timeout=0.1)


def test_stop_timeout_is_clear(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    status = _status(tmp_path)
    monkeypatch.setattr(client, "read_status", lambda _: status)
    monkeypatch.setattr(client, "_roundtrip", lambda *_args, **_kwargs: DaemonResponse(True))

    with pytest.raises(client.DaemonError, match="did not stop"):
        client.stop_daemon(tmp_path, timeout=0)


def test_check_retries_one_connection_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = _status(tmp_path, instance="first")
    second = _status(tmp_path, instance="second")
    statuses = iter((first, second))
    calls = 0

    def roundtrip(*_args: object, **_kwargs: object) -> DaemonResponse:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise client.DaemonError("crashed")
        return DaemonResponse(True, b"ok", b"", 0)

    monkeypatch.setattr(client, "start_daemon", lambda _: next(statuses))
    monkeypatch.setattr(client, "remove_unusable_status", lambda *_: None)
    monkeypatch.setattr(client, "_roundtrip", roundtrip)

    result = client.check_daemon(CheckRequest(tmp_path))

    assert result.stdout == b"ok"
    assert calls == 2


def test_check_surfaces_server_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client, "start_daemon", lambda _: _status(tmp_path))
    monkeypatch.setattr(
        client,
        "_roundtrip",
        lambda *_args, **_kwargs: DaemonResponse(False, error="server rejected request"),
    )

    with pytest.raises(client.DaemonError, match="server rejected"):
        client.check_daemon(CheckRequest(tmp_path), retry=False)


def test_ping_rejects_reused_pid_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    original = _status(tmp_path)
    status = DaemonStatus(
        original.schema,
        original.protocol,
        original.taut_version,
        original.plugin_environment,
        original.canonical_root,
        original.pid,
        "expected-start",
        original.instance_id,
        original.port,
        original.token,
        original.started_at,
        original.last_used_at,
    )
    monkeypatch.setattr(client, "process_start_identity", lambda _: "different-start")

    assert not client._ping(status)


def test_roundtrip_translates_socket_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def timeout(*_args: object, **_kwargs: object) -> socket.socket:
        raise TimeoutError

    status = _status(tmp_path)
    monkeypatch.setattr(socket, "create_connection", timeout)

    with pytest.raises(client.DaemonError, match="timed out"):
        client._roundtrip(status, client._request(status, "ping"))
