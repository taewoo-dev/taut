"""Secure per-project daemon status and startup serialization."""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
import time
from collections.abc import Generator
from contextlib import contextmanager, suppress
from os import getenv
from pathlib import Path

import msgspec

from taut import __version__
from taut.daemon_protocol import PROTOCOL_VERSION, STATUS_SCHEMA_VERSION
from taut.policy.packs import plugin_environment_digest


class DaemonStatus(msgspec.Struct, forbid_unknown_fields=True, frozen=True):
    schema: int
    protocol: int
    taut_version: str
    plugin_environment: str
    canonical_root: str
    pid: int
    process_start: str | None
    instance_id: str
    port: int
    token: str
    started_at: float
    last_used_at: float


def runtime_directory(root: Path) -> Path:
    canonical = str(root.resolve())
    digest = hashlib.sha256(canonical.encode()).hexdigest()[:24]
    override = _environment_value("TAUT_RUNTIME_DIR")
    if override:
        base = Path(override).resolve()
    else:
        runtime = _environment_value("XDG_RUNTIME_DIR")
        owner = str(os.getuid()) if hasattr(os, "getuid") else "user"
        base = (
            Path(runtime) / "pytaut" if runtime else Path(tempfile.gettempdir()) / f"pytaut-{owner}"
        )
    _secure_directory(base)
    project = base / digest
    _secure_directory(project)
    return project


def status_path(root: Path) -> Path:
    return runtime_directory(root) / "status.json"


def lock_path(root: Path) -> Path:
    return runtime_directory(root) / "startup.lock"


def read_status(root: Path) -> DaemonStatus | None:
    path = status_path(root)
    try:
        metadata = path.lstat()
        mode = metadata.st_mode
        if not stat.S_ISREG(mode) or stat.S_ISLNK(mode):
            return None
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            return None
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            return None
        status = msgspec.json.decode(path.read_bytes(), type=DaemonStatus, strict=True)
    except (OSError, msgspec.DecodeError, msgspec.ValidationError):
        return None
    if (
        status.canonical_root != str(root.resolve())
        or status.pid < 1
        or not 0 < status.port < 65536
        or len(status.token) < 32
        or not status.instance_id
    ):
        return None
    return status


def compatible(status: DaemonStatus, root: Path) -> bool:
    return (
        status.schema == STATUS_SCHEMA_VERSION
        and status.protocol == PROTOCOL_VERSION
        and status.taut_version == __version__
        and status.plugin_environment == plugin_environment_digest()
        and status.canonical_root == str(root.resolve())
    )


def write_status(root: Path, status: DaemonStatus) -> None:
    path = status_path(root)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{status.instance_id}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, 0o600)
    try:
        payload = msgspec.json.encode(status)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def remove_status_if_owned(root: Path, expected: DaemonStatus) -> bool:
    current = read_status(root)
    if current != expected:
        return False
    try:
        status_path(root).unlink()
    except FileNotFoundError:
        return False
    return True


def remove_unusable_status(root: Path, observed: DaemonStatus | None) -> None:
    path = status_path(root)
    current = read_status(root)
    if observed is not None and current != observed:
        return
    if observed is None and current is not None:
        return
    with suppress(FileNotFoundError):
        path.unlink()


@contextmanager
def startup_lock(root: Path, *, timeout: float = 15.0) -> Generator[None, None, None]:
    path = lock_path(root)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise OSError("daemon startup lock is not a regular file")
    os.chmod(path, 0o600)
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                _lock_descriptor(descriptor)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("timed out waiting for daemon startup lock") from None
                time.sleep(0.05)
        yield
    finally:
        _unlock_descriptor(descriptor)
        os.close(descriptor)


def process_start_identity(pid: int) -> str | None:
    proc_stat = Path(f"/proc/{pid}/stat")
    try:
        raw = proc_stat.read_text()
        return f"linux:{raw[raw.rfind(')') + 2 :].split()[19]}"
    except (OSError, IndexError):
        pass
    return None


def _secure_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise OSError(f"daemon runtime path is not a secure directory: {path}")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise PermissionError(f"daemon runtime directory has another owner: {path}")
    os.chmod(path, 0o700)


def _environment_value(name: str) -> str | None:
    return getenv(name)


if os.name == "nt":
    import msvcrt

    _ms_locking = getattr(msvcrt, "locking")  # noqa: B009
    _ms_nonblocking = int(getattr(msvcrt, "LK_NBLCK"))  # noqa: B009
    _ms_unlock = int(getattr(msvcrt, "LK_UNLCK"))  # noqa: B009

    def _lock_descriptor(descriptor: int) -> None:
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            _ms_locking(descriptor, _ms_nonblocking, 1)
        except OSError as error:
            raise BlockingIOError from error

    def _unlock_descriptor(descriptor: int) -> None:
        os.lseek(descriptor, 0, os.SEEK_SET)
        with suppress(OSError):
            _ms_locking(descriptor, _ms_unlock, 1)

else:
    import fcntl

    def _lock_descriptor(descriptor: int) -> None:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock_descriptor(descriptor: int) -> None:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
