"""Atomic persistence for a fully reviewed init proposal."""

from __future__ import annotations

import os
import tempfile
import tomllib
from pathlib import Path

from taut.loading.errors import PolicyConfigError


def write_reviewed_configuration(
    project_root: Path, config_path: Path, status: str, proposal_toml: str
) -> None:
    if status != "ready":
        raise PolicyConfigError("init has unresolved questions; provide --answers before --write")
    root = project_root.resolve()
    target = config_path if config_path.is_absolute() else root / config_path
    existing = target.read_text() if target.exists() else ""
    if target.name == "pyproject.toml":
        if existing:
            try:
                raw = tomllib.loads(existing)
            except tomllib.TOMLDecodeError as error:
                raise PolicyConfigError(f"cannot read pyproject.toml: {error}") from error
            tool = raw.get("tool", {})
            if isinstance(tool, dict) and "taut" in tool:
                raise PolicyConfigError(
                    "[tool.taut] already exists; use 'taut audit .' or 'taut config migrate .'"
                )
        content = existing.rstrip() + ("\n\n" if existing.strip() else "") + proposal_toml
    else:
        if target.exists():
            raise PolicyConfigError(f"configuration already exists: {target}")
        content = proposal_toml.replace("tool.taut.", "").replace("[tool.taut]", "").lstrip()
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(descriptor, "w") as temporary:
            temporary.write(content.rstrip() + "\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, target)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
