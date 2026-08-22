"""Single-project daemon process serving a resident check session."""

from __future__ import annotations

import argparse
import os
import secrets
import signal
import socket
import time
from contextlib import suppress
from pathlib import Path

from taut import __version__
from taut.check_service import CheckRequest, ResidentCheckSession
from taut.daemon_protocol import (
    PROTOCOL_VERSION,
    REQUEST_TIMEOUT_SECONDS,
    STATUS_SCHEMA_VERSION,
    CheckWire,
    CountersWire,
    DaemonRequest,
    DaemonResponse,
    TimingWire,
    receive_request,
    send_response,
)
from taut.daemon_state import (
    DaemonStatus,
    process_start_identity,
    remove_status_if_owned,
    write_status,
)
from taut.domain.location import ConfigPath

DEFAULT_IDLE_TIMEOUT_SECONDS = 30 * 60.0


class DaemonServer:
    def __init__(self, root: Path, *, idle_timeout: float = DEFAULT_IDLE_TIMEOUT_SECONDS) -> None:
        self.root = root.resolve()
        self.idle_timeout = idle_timeout
        self._stop = False
        self._listener: socket.socket | None = None
        self._session: ResidentCheckSession | None = None
        self._status: DaemonStatus | None = None

    def serve(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(32)
        listener.settimeout(0.25)
        self._listener = listener
        now = time.time()
        status = DaemonStatus(
            schema=STATUS_SCHEMA_VERSION,
            protocol=PROTOCOL_VERSION,
            taut_version=__version__,
            canonical_root=str(self.root),
            pid=os.getpid(),
            process_start=process_start_identity(os.getpid()),
            instance_id=secrets.token_hex(16),
            port=int(listener.getsockname()[1]),
            token=secrets.token_urlsafe(32),
            started_at=now,
            last_used_at=now,
        )
        self._status = status
        write_status(self.root, status)
        self._session = ResidentCheckSession(self.root)
        self._install_signal_handlers()
        try:
            while not self._stop:
                if time.time() - self._status.last_used_at >= self.idle_timeout:
                    break
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                self._serve_connection(connection)
        finally:
            self.close()

    def close(self) -> None:
        self._stop = True
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        if self._session is not None:
            self._session.close()
            self._session = None
        if self._status is not None:
            remove_status_if_owned(self.root, self._status)

    def _serve_connection(self, connection: socket.socket) -> None:
        with connection:
            connection.settimeout(REQUEST_TIMEOUT_SECONDS)
            try:
                request = receive_request(connection)
                response = self._dispatch(request)
            except Exception as error:
                response = DaemonResponse(ok=False, error=_error_message(error))
            with suppress(OSError, ValueError):
                send_response(connection, response)

    def _dispatch(self, request: DaemonRequest) -> DaemonResponse:
        status = self._require_status()
        if not secrets.compare_digest(request.token, status.token):
            raise PermissionError("daemon authentication failed")
        if request.protocol != PROTOCOL_VERSION or request.taut_version != __version__:
            raise ValueError("daemon protocol or version mismatch")
        if str(Path(request.root).resolve()) != str(self.root):
            raise ValueError("daemon project root mismatch")
        self._touch()
        if request.action == "ping":
            return DaemonResponse(ok=True, exit_code=0)
        if request.action == "stop":
            self._stop = True
            return DaemonResponse(ok=True, exit_code=0)
        if request.action != "check" or request.check is None:
            raise ValueError("unknown daemon action")
        return self._check(request.check)

    def _check(self, wire: CheckWire) -> DaemonResponse:
        if wire.output_format not in {"text", "json"} or wire.width < 60:
            raise ValueError("invalid daemon check rendering options")
        if self._session is None:
            raise RuntimeError("daemon resident session is unavailable")
        result = self._session.check(
            CheckRequest(
                project_root=self.root,
                config_path=ConfigPath(wire.config_path) if wire.config_path else None,
                output_format=wire.output_format,
                show_inactive=wire.show_inactive,
                verbose=wire.verbose,
                use_color=wire.use_color,
                width=wire.width,
            )
        )
        counters = result.counters
        return DaemonResponse(
            ok=True,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            timings=tuple(TimingWire(item.name, item.milliseconds) for item in result.timings),
            counters=CountersWire(
                counters.reparsed_modules,
                counters.reused_modules,
                counters.recomputed_providers,
                counters.reused_providers,
                counters.recomputed_evaluations,
                counters.reused_evaluations,
                counters.full_policy_rerun,
            ),
        )

    def _touch(self) -> None:
        prior = self._require_status()
        current = DaemonStatus(
            prior.schema,
            prior.protocol,
            prior.taut_version,
            prior.canonical_root,
            prior.pid,
            prior.process_start,
            prior.instance_id,
            prior.port,
            prior.token,
            prior.started_at,
            time.time(),
        )
        self._status = current
        write_status(self.root, current)

    def _require_status(self) -> DaemonStatus:
        if self._status is None:
            raise RuntimeError("daemon status is unavailable")
        return self._status

    def _install_signal_handlers(self) -> None:
        def stop(_: int, __: object) -> None:
            self._stop = True

        for number in (signal.SIGINT, signal.SIGTERM):
            signal.signal(number, stop)


def _error_message(error: Exception) -> str:
    return f"{error.__class__.__name__}: {error}"


def main(argv: tuple[str, ...] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("root")
    parser.add_argument("--idle-timeout", type=float, default=DEFAULT_IDLE_TIMEOUT_SECONDS)
    namespace = parser.parse_args(argv)
    if namespace.idle_timeout <= 0:
        raise ValueError("idle timeout must be positive")
    DaemonServer(Path(namespace.root), idle_timeout=namespace.idle_timeout).serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
