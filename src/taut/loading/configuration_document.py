from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from taut.domain.location import ConfigPath
from taut.domain.provider_ids import BUILTIN_BACKEND_PROVIDER_IDS
from taut.loading.errors import PolicyConfigError

PYPROJECT_CONFIG_PATH = ConfigPath("pyproject.toml")
LEGACY_CONFIG_PATH = ConfigPath(".policy/policy.toml")

_TOOL_KEYS = frozenset(
    {
        "extend",
        "schema_version",
        "packs",
        "providers",
        "strict",
        "cache",
        "include",
        "exclude",
        "source_roots",
        "default_zone",
        "max_lines",
        "role_max_lines",
        "roles",
        "zones",
        "allow",
        "effects",
        "rules",
        "rule_zones",
        "approvals",
        "transaction",
        "boundaries",
        "layers",
        "external",
        "database",
        "enum",
        "boundary_extensions",
        "code_conventions",
        "security",
        "assurance",
        "exclusions",
    }
)
_LAYER_KEYS = {
    "entry": "entry_roles",
    "service": "service_roles",
    "contract": "contract_roles",
    "adapter": "adapter_roles",
    "query": "query_roles",
    "model": "model_roles",
    "bootstrap": "bootstrap_roles",
    "implementation_construction": "implementation_construction_roles",
    "scoped_construction": "scoped_construction_roles",
    "configuration": "configuration_roles",
    "dependency_registration": "dependency_registration_roles",
    "raw_query": "raw_query_roles",
}
_EXTERNAL_KEYS = {
    "modules": "external_modules",
    "client_constructors": "external_client_constructors",
    "timeout_calls": "http_timeout_calls",
    "logged_calls": "logged_external_calls",
    "wrappers": "external_call_wrappers",
}
_DATABASE_KEYS = {
    "modules": "database_modules",
    "statement_calls": "database_statement_calls",
    "session_types": "session_type_symbols",
    "raw_sql_calls": "raw_sql_calls",
    "raw_query_roles": "raw_query_roles",
    "raw_query_wrappers": "raw_query_wrappers",
    "schema_roles": "schema_sql_roles",
    "schema_argument_names": "schema_sql_argument_names",
    "schema_parent_calls": "schema_sql_parent_calls",
    "execution_methods": "raw_sql_execution_methods",
    "owner_names": "database_owner_names",
    "primitive_methods": "database_primitive_methods",
    "query_write_prefixes": "query_write_method_prefixes",
}
_ENUM_KEYS = {
    "shared_modules": "shared_enum_modules",
    "uppercase_value_exceptions": "uppercase_enum_exceptions",
    "non_string_exceptions": "non_str_enum_exceptions",
    "native_enum_false_exceptions": "native_enum_false_exceptions",
    "native_enum_no_constraint_exceptions": "native_enum_no_constraint_exceptions",
}


@dataclass(frozen=True)
class ConfigurationDocument:
    root: dict[str, object]
    path: ConfigPath
    strict: bool


def read_configuration_document(
    project_root: Path,
    requested_path: ConfigPath | None,
) -> ConfigurationDocument:
    if requested_path is not None:
        absolute = _absolute_config_path(project_root, requested_path)
        raw = _read_toml_path(absolute, requested_path.value)
        return _document_from_raw(_resolve_extends(raw, absolute, ()), requested_path)

    pyproject = project_root / PYPROJECT_CONFIG_PATH.value
    if pyproject.is_file():
        raw = _read_toml(project_root, PYPROJECT_CONFIG_PATH)
        if _tool_section(raw) is not None:
            return _document_from_raw(_resolve_extends(raw, pyproject, ()), PYPROJECT_CONFIG_PATH)

    legacy = project_root / LEGACY_CONFIG_PATH.value
    if legacy.is_file():
        return _document_from_raw(_read_toml(project_root, LEGACY_CONFIG_PATH), LEGACY_CONFIG_PATH)
    raise PolicyConfigError("configuration is missing: add [tool.taut] to pyproject.toml")


def _read_toml(project_root: Path, config_path: ConfigPath) -> dict[str, object]:
    absolute = _absolute_config_path(project_root, config_path)
    return _read_toml_path(absolute, config_path.value)


def _absolute_config_path(project_root: Path, config_path: ConfigPath) -> Path:
    return Path(config_path.value) if config_path.is_absolute else project_root / config_path.value


def _read_toml_path(absolute: Path, display: str) -> dict[str, object]:
    if not absolute.is_file():
        raise PolicyConfigError(f"configuration file is missing: {display}")
    try:
        raw: object = tomllib.loads(absolute.read_text())
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise PolicyConfigError(f"cannot read {display}: {error}") from error
    return _table(raw, "config")


def _resolve_extends(
    raw: dict[str, object], config_file: Path, chain: tuple[Path, ...]
) -> dict[str, object]:
    """Resolve explicit configuration inheritance before schema normalization."""
    canonical = config_file.resolve()
    if canonical in chain:
        cycle = " -> ".join(str(path) for path in (*chain, canonical))
        raise PolicyConfigError(f"configuration extend cycle: {cycle}")
    section = _tool_section(raw)
    if section is None or "extend" not in section:
        return raw
    raw_extend = section.get("extend")
    if not isinstance(raw_extend, str) or not raw_extend:
        raise PolicyConfigError("tool.taut.extend must be a non-empty file path")
    extension_path = Path(raw_extend)
    base_path = (
        extension_path if extension_path.is_absolute() else canonical.parent / extension_path
    ).resolve()
    base_raw = _read_toml_path(base_path, raw_extend)
    base = _resolve_extends(base_raw, base_path, (*chain, canonical))
    base_section = _tool_section(base)
    if base_section is None:
        raise PolicyConfigError(f"extended configuration has no [tool.taut]: {raw_extend}")
    child_section = dict(section)
    child_section.pop("extend")
    merged_section = _deep_merge(base_section, child_section)
    merged = dict(raw)
    tool = dict(_table(merged.get("tool", {}), "tool"))
    tool["taut"] = merged_section
    merged["tool"] = tool
    return merged


def _deep_merge(base: dict[str, object], child: dict[str, object]) -> dict[str, object]:
    merged = dict(base)
    for key, value in child.items():
        inherited = merged.get(key)
        if isinstance(inherited, dict) and isinstance(value, dict):
            inherited_value = cast(object, inherited)
            child_value = cast(object, value)
            merged[key] = _deep_merge(
                _table(inherited_value, f"tool.taut.{key}"),
                _table(child_value, f"tool.taut.{key}"),
            )
        else:
            merged[key] = value
    merged.pop("extend", None)
    return merged


def _document_from_raw(raw: dict[str, object], path: ConfigPath) -> ConfigurationDocument:
    section = _tool_section(raw)
    if section is None:
        return ConfigurationDocument(raw, path, _boolean(raw.get("strict", True), "strict"))
    return ConfigurationDocument(
        _normalize_tool_section(section), path, _boolean(section.get("strict", True), "strict")
    )


def _tool_section(raw: dict[str, object]) -> dict[str, object] | None:
    tool = raw.get("tool")
    if tool is None:
        return None
    tool_table = _table(tool, "tool")
    section = tool_table.get("taut")
    if section is None:
        return None
    return _table(section, "tool.taut")


def _normalize_tool_section(section: dict[str, object]) -> dict[str, object]:
    _reject_unknown(section, _TOOL_KEYS, "tool.taut")
    root: dict[str, object] = {
        "schema_version": section.get("schema_version", 5),
        "packs": section.get("packs", ["taut.backend"]),
        "providers": section.get("providers", list(BUILTIN_BACKEND_PROVIDER_IDS)),
    }

    if "cache" in section:
        root["cache"] = section["cache"]

    project_keys = ("include", "exclude", "source_roots", "default_zone")
    project = {key: section[key] for key in project_keys if key in section}
    if project:
        root["project"] = project

    roles = _table(section.get("roles", {}), "tool.taut.roles")
    root["roles"] = [_normalized_role(name, value) for name, value in roles.items()]
    zones = _table(section.get("zones", {}), "tool.taut.zones")
    root["zones"] = [{"name": name, "patterns": patterns} for name, patterns in zones.items()]

    allow = _table(section.get("allow", {}), "tool.taut.allow")
    root["architecture"] = {"allow": allow}

    if "effects" in section:
        root["effects"] = section["effects"]
    if "rules" in section:
        root["rules"] = section["rules"]
    if "rule_zones" in section:
        root["rule_zones"] = section["rule_zones"]
    if "approvals" in section:
        root["approvals"] = section["approvals"]
    if "transaction" in section:
        root["transaction"] = section["transaction"]
    if "boundaries" in section:
        root["boundaries"] = section["boundaries"]
    if "security" in section:
        root["security"] = section["security"]
    if "assurance" in section:
        root["assurance"] = section["assurance"]
    if "exclusions" in section:
        root["exclusions"] = section["exclusions"]

    size: dict[str, object] = {}
    if "max_lines" in section:
        size["default_max_lines"] = section["max_lines"]
    if "role_max_lines" in section:
        size["role_max_lines"] = section["role_max_lines"]
    if size:
        root["size"] = size

    extensions = dict(
        _table(section.get("boundary_extensions", {}), "tool.taut.boundary_extensions")
    )
    _merge_aliases(extensions, section.get("layers", {}), _LAYER_KEYS, "layers")
    _merge_aliases(extensions, section.get("external", {}), _EXTERNAL_KEYS, "external")
    _merge_aliases(extensions, section.get("database", {}), _DATABASE_KEYS, "database")
    if extensions:
        root["boundary_extensions"] = extensions

    conventions = dict(_table(section.get("code_conventions", {}), "tool.taut.code_conventions"))
    _merge_aliases(conventions, section.get("enum", {}), _ENUM_KEYS, "enum")
    if conventions:
        root["code_conventions"] = conventions
    return root


def _normalized_role(name: str, value: object) -> dict[str, object]:
    if isinstance(value, list):
        return {"name": name, "include": value}
    table = _table(value, f"tool.taut.roles.{name}")
    _reject_unknown(table, frozenset({"include", "exclude", "priority"}), f"roles.{name}")
    return {
        "name": name,
        "include": table.get("include", []),
        "exclude": table.get("exclude", []),
        "priority": table.get("priority", 0),
    }


def _merge_aliases(
    target: dict[str, object],
    value: object,
    aliases: dict[str, str],
    label: str,
) -> None:
    table = _table(value, f"tool.taut.{label}")
    _reject_unknown(table, frozenset(aliases), f"tool.taut.{label}")
    for name, item in table.items():
        target_name = aliases[name]
        if target_name in target:
            raise PolicyConfigError(f"{label}.{name} is configured twice")
        target[target_name] = item


def _table(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise PolicyConfigError(f"{label} must be a table")
    unknown = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in unknown):
        raise PolicyConfigError(f"{label} must be a table")
    return cast(dict[str, object], value)


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyConfigError(f"{label} must be true or false")
    return value


def _reject_unknown(table: dict[str, object], allowed: frozenset[str], label: str) -> None:
    unknown = set(table).difference(allowed)
    if unknown:
        raise PolicyConfigError(f"unknown {label} keys: {', '.join(sorted(unknown))}")
