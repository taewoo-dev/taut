from __future__ import annotations

import re
from pathlib import Path

from taut.domain.location import ConfigPath
from taut.domain.provider_ids import BUILTIN_BACKEND_PROVIDER_IDS
from taut.loading.configuration_document import LEGACY_CONFIG_PATH, PYPROJECT_CONFIG_PATH
from taut.loading.errors import PolicyConfigError

_DEFAULT_PROVIDERS = ", ".join(f'"{provider_id}"' for provider_id in BUILTIN_BACKEND_PROVIDER_IDS)

_SCHEMA_LINE = re.compile(r"(?m)^schema_version\s*=\s*\d+\s*$")
_PACKS_LINE = re.compile(r"(?m)^packs\s*=.*$")
_PROVIDERS_LINE = re.compile(r"(?m)^providers\s*=.*$")
_TOOL_HEADER = re.compile(r"(?m)^\[tool\.taut\]\s*$")
_ASSURANCE_HEADER = re.compile(r"(?m)^\[(?:tool\.taut\.)?assurance\.features\]\s*$")
_ASSURANCE_FEATURES = (
    "api",
    "schema",
    "dto",
    "snapshot",
    "exception_registry",
    "enum",
    "database",
    "transaction",
    "external_calls",
    "security",
    "tests",
    "migrations",
    "scripts",
)


def migrate_configuration_text(
    project_root: Path,
    requested_path: ConfigPath | None = None,
) -> tuple[ConfigPath, str]:
    path = _resolve_source(project_root, requested_path)
    absolute = Path(path.value) if path.is_absolute else project_root / path.value
    try:
        text = absolute.read_text()
    except (OSError, UnicodeError) as error:
        raise PolicyConfigError(f"cannot read {path.value}: {error}") from error

    migrated = _migrate_pyproject(text) if _TOOL_HEADER.search(text) else _migrate_standalone(text)
    if not migrated.endswith("\n"):
        migrated += "\n"
    return path, migrated


def write_migrated_configuration(path: Path, text: str, *, force: bool) -> None:
    if path.exists() and not force:
        raise PolicyConfigError(f"output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _resolve_source(project_root: Path, requested: ConfigPath | None) -> ConfigPath:
    if requested is not None:
        return requested
    if (project_root / PYPROJECT_CONFIG_PATH.value).is_file():
        return PYPROJECT_CONFIG_PATH
    if (project_root / LEGACY_CONFIG_PATH.value).is_file():
        return LEGACY_CONFIG_PATH
    raise PolicyConfigError("configuration is missing: add [tool.taut] to pyproject.toml")


def _migrate_pyproject(text: str) -> str:
    match = _TOOL_HEADER.search(text)
    if match is None:
        raise PolicyConfigError("pyproject.toml does not contain [tool.taut]")
    additions: list[str] = []
    section_end = _next_table_offset(text, match.end())
    section = text[match.end() : section_end]
    if _SCHEMA_LINE.search(section) is None:
        additions.append("schema_version = 4")
    else:
        section = _SCHEMA_LINE.sub("schema_version = 4", section, count=1)
    if _PACKS_LINE.search(section) is None:
        additions.append('packs = ["taut.backend"]')
    if _PROVIDERS_LINE.search(section) is None:
        additions.append(f"providers = [{_DEFAULT_PROVIDERS}]")
    prefix = text[: match.end()]
    if additions:
        prefix += "\n" + "\n".join(additions)
    migrated = prefix + section + text[section_end:]
    if _ASSURANCE_HEADER.search(migrated) is None:
        migrated = migrated.rstrip() + "\n\n" + _assurance_block("tool.taut.")
    return migrated


def _migrate_standalone(text: str) -> str:
    migrated = _SCHEMA_LINE.sub("schema_version = 4", text, count=1)
    if migrated == text:
        migrated = "schema_version = 4\n" + migrated
    if _PACKS_LINE.search(migrated) is None:
        schema = _SCHEMA_LINE.search(migrated)
        if schema is None:
            raise PolicyConfigError("cannot insert v4 rule packs")
        migrated = (
            migrated[: schema.end()] + '\npacks = ["taut.backend"]' + migrated[schema.end() :]
        )
    if _PROVIDERS_LINE.search(migrated) is None:
        packs = _PACKS_LINE.search(migrated)
        if packs is None:
            raise PolicyConfigError("cannot insert v4 fact providers")
        migrated = (
            migrated[: packs.end()]
            + f"\nproviders = [{_DEFAULT_PROVIDERS}]"
            + migrated[packs.end() :]
        )
    if _ASSURANCE_HEADER.search(migrated) is None:
        migrated = migrated.rstrip() + "\n\n" + _assurance_block("")
    return migrated


def _assurance_block(prefix: str) -> str:
    lines = [f"[{prefix}assurance.features]"]
    lines.extend(f'{feature} = "absent"' for feature in _ASSURANCE_FEATURES)
    return "\n".join(lines) + "\n"


def _next_table_offset(text: str, start: int) -> int:
    match = re.search(r"(?m)^\[", text[start:])
    return len(text) if match is None else start + match.start()
