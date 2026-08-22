"""Lifecycle and request client for the supervised local daemon."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path
from subprocess import Popen
from typing import cast

from taut import __version__
from taut.check_service import CheckCounters, CheckRequest, CheckResult, StageTiming
from taut.daemon_protocol import (
    PROTOCOL_VERSION,
    REQUEST_TIMEOUT_SECONDS,
    CheckWire,
    CountersWire,
    DaemonRequest,
    DaemonResponse,
    receive_response,
    send_request,
)
from taut.daemon_server import DEFAULT_IDLE_TIMEOUT_SECONDS
from taut.daemon_state import (
    DaemonStatus,
    compatible,
    process_start_identity,
    read_status,
    remove_unusable_status,
    startup_lock,
)

START_TIMEOUT_SECONDS = 15.0
CONNECT_TIMEOUT_SECONDS = 2.0
STOP_TIMEOUT_SECONDS = 5.0
_OWNED_PROCESSES: dict[int, Popen[bytes]] = {}


class DaemonError(RuntimeError):
    pass


def start_daemon(
    root: Path,
    *,
    timeout: float = START_TIMEOUT_SECONDS,
    idle_timeout: float = DEFAULT_IDLE_TIMEOUT_SECONDS,
) -> DaemonStatus:
    canonical = root.resolve()
    with startup_lock(canonical, timeout=timeout):
        existing = read_status(canonical)
        if existing is not None and compatible(existing, canonical) and _ping(existing):
            return existing
        _collect_owned_processes()
        remove_unusable_status(canonical, existing)
        process = _spawn(canonical, idle_timeout)
        _OWNED_PROCESSES[process.pid] = process
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise DaemonError("daemon exited during startup")
            status = read_status(canonical)
            if status is not None and compatible(status, canonical) and _ping(status):
                return status
            time.sleep(0.05)
        _stop_owned_process(process)
        raise DaemonError("timed out waiting for daemon startup")


def daemon_status(root: Path) -> DaemonStatus | None:
    canonical = root.resolve()
    status = read_status(canonical)
    if status is None or not compatible(status, canonical) or not _ping(status):
        _collect_owned_processes()
        return None
    return read_status(canonical) or status


def stop_daemon(root: Path, *, timeout: float = STOP_TIMEOUT_SECONDS) -> bool:
    canonical = root.resolve()
    status = read_status(canonical)
    if status is None or not compatible(status, canonical):
        return False
    response = _roundtrip(status, _request(status, "stop"), timeout=CONNECT_TIMEOUT_SECONDS)
    if not response.ok:
        raise DaemonError(response.error or "daemon refused stop request")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = read_status(canonical)
        if current is None or current.instance_id != status.instance_id:
            _wait_owned_process(status.pid)
            return True
        time.sleep(0.05)
    raise DaemonError("daemon did not stop before timeout")


def restart_daemon(root: Path) -> DaemonStatus:
    with suppress(DaemonError):
        stop_daemon(root)
    return start_daemon(root)


def check_daemon(request: CheckRequest, *, retry: bool = True) -> CheckResult:
    root = request.project_root.resolve()
    status = start_daemon(root)
    try:
        response = _roundtrip(status, _check_request(status, request))
    except (DaemonError, OSError, ConnectionError, TimeoutError):
        if not retry:
            raise
        remove_unusable_status(root, status)
        status = start_daemon(root)
        response = _roundtrip(status, _check_request(status, request))
    if not response.ok:
        raise DaemonError(response.error or "daemon check failed")
    counters = cast(CountersWire, response.counters)  # type: ignore[redundant-cast]
    return CheckResult(
        stdout=response.stdout,
        stderr=response.stderr,
        exit_code=response.exit_code,
        report=None,
        timings=tuple(StageTiming(item.name, item.milliseconds) for item in response.timings),
        counters=CheckCounters(
            counters.reparsed_modules,
            counters.reused_modules,
            counters.recomputed_providers,
            counters.reused_providers,
            counters.recomputed_evaluations,
            counters.reused_evaluations,
            counters.full_policy_rerun,
        ),
    )


def _check_request(status: DaemonStatus, request: CheckRequest) -> DaemonRequest:
    config = request.config_path.value if request.config_path is not None else None
    return _request(
        status,
        "check",
        CheckWire(
            config,
            request.output_format,
            request.show_inactive,
            request.verbose,
            request.use_color,
            request.width,
        ),
    )


def _request(status: DaemonStatus, action: str, check: CheckWire | None = None) -> DaemonRequest:
    return DaemonRequest(
        action=action,
        token=status.token,
        root=status.canonical_root,
        protocol=PROTOCOL_VERSION,
        taut_version=__version__,
        check=check,
    )


def _ping(status: DaemonStatus) -> bool:
    if status.process_start is not None:
        current = process_start_identity(status.pid)
        if current != status.process_start:
            return False
    try:
        return _roundtrip(status, _request(status, "ping"), timeout=CONNECT_TIMEOUT_SECONDS).ok
    except (DaemonError, OSError, ConnectionError, TimeoutError):
        return False


def _roundtrip(
    status: DaemonStatus,
    request: DaemonRequest,
    *,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
) -> DaemonResponse:
    try:
        with socket.create_connection(("127.0.0.1", status.port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            send_request(connection, request)
            return receive_response(connection)
    except TimeoutError as error:
        raise DaemonError("daemon request timed out") from error
    except (OSError, ValueError) as error:
        raise DaemonError(f"daemon connection failed: {error}") from error


def _spawn(root: Path, idle_timeout: float) -> Popen[bytes]:
    command = (
        sys.executable,
        "-m",
        "taut.daemon_server",
        str(root),
        "--idle-timeout",
        str(idle_timeout),
    )
    flags = 0
    if os.name == "nt":
        flags = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP")) | int(  # noqa: B009
            getattr(subprocess, "DETACHED_PROCESS")  # noqa: B009
        )
    return Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=flags,
        start_new_session=os.name != "nt",
    )


def _stop_owned_process(process: Popen[bytes]) -> None:
    _OWNED_PROCESSES.pop(process.pid, None)
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def _wait_owned_process(pid: int) -> None:
    process = _OWNED_PROCESSES.pop(pid, None)
    if process is None:
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        _OWNED_PROCESSES[pid] = process


def _collect_owned_processes() -> None:
    for pid, process in tuple(_OWNED_PROCESSES.items()):
        if process.poll() is not None:
            _OWNED_PROCESSES.pop(pid, None)
