from __future__ import annotations

import os
from pathlib import Path

import pytest

from taut import __version__
from taut.daemon_state import (
    DaemonStatus,
    compatible,
    read_status,
    remove_status_if_owned,
    remove_unusable_status,
    status_path,
    write_status,
)


def _status(root: Path, instance: str = "one") -> DaemonStatus:
    return DaemonStatus(
        1,
        1,
        __version__,
        str(root.resolve()),
        os.getpid(),
        None,
        instance,
        12345,
        "x" * 43,
        1.0,
        1.0,
    )


def test_status_permissions_and_owned_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TAUT_RUNTIME_DIR", str(tmp_path / "runtime"))
    root = tmp_path / "project"
    root.mkdir()
    first = _status(root)
    write_status(root, first)

    assert not remove_status_if_owned(root, _status(root, "other"))
    assert remove_status_if_owned(root, first)
    assert not remove_status_if_owned(root, first)


def test_status_rejects_insecure_mode_and_incompatible_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TAUT_RUNTIME_DIR", str(tmp_path / "runtime"))
    root = tmp_path / "project"
    root.mkdir()
    current = _status(root)
    write_status(root, current)
    os.chmod(status_path(root), 0o644)

    assert read_status(root) is None
    incompatible = DaemonStatus(
        current.schema,
        current.protocol,
        "different",
        current.canonical_root,
        current.pid,
        current.process_start,
        current.instance_id,
        current.port,
        current.token,
        current.started_at,
        current.last_used_at,
    )
    assert not compatible(incompatible, root)


def test_status_rejects_malformed_and_invalid_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TAUT_RUNTIME_DIR", str(tmp_path / "runtime"))
    root = tmp_path / "project"
    root.mkdir()
    path = status_path(root)
    path.write_bytes(b"not-json")
    os.chmod(path, 0o600)
    assert read_status(root) is None

    invalid = _status(root)
    invalid = DaemonStatus(
        invalid.schema,
        invalid.protocol,
        invalid.taut_version,
        invalid.canonical_root,
        0,
        invalid.process_start,
        invalid.instance_id,
        invalid.port,
        invalid.token,
        invalid.started_at,
        invalid.last_used_at,
    )
    write_status(root, invalid)
    assert read_status(root) is None


def test_remove_unusable_status_preserves_changed_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TAUT_RUNTIME_DIR", str(tmp_path / "runtime"))
    root = tmp_path / "project"
    root.mkdir()
    current = _status(root)
    write_status(root, current)

    remove_unusable_status(root, _status(root, "stale"))
    assert read_status(root) == current
    remove_unusable_status(root, None)
    assert read_status(root) == current
    remove_unusable_status(root, current)
    assert read_status(root) is None
