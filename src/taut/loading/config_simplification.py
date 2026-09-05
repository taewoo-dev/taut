"""Read-only compact configuration proposals with semantic equivalence checks."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import cast

from taut.configuration.model import ProjectConfiguration
from taut.configuration.path_patterns import compact_patterns
from taut.domain.location import ConfigPath
from taut.loading.config_loader import load_project_configuration
from taut.loading.config_values import table, table_list
from taut.loading.configuration_document import (
    parse_configuration_document,
    read_configuration_values,
)
from taut.loading.errors import PolicyConfigError

_DEFAULT_SECTIONS = (
    "cache",
    "layers",
    "external",
    "database",
    "security",
    "code_conventions",
    "assurance",
)
_DEFAULT_KEYS = (
    "packs",
    "providers",
    "strict",
    "source_roots",
    "default_zone",
    "max_lines",
    "include",
)


def semantic_digest(config: ProjectConfiguration) -> str:
    """Ignore redundant matcher syntax and order-independent role/zone declarations."""
    manifest = replace(
        config.manifest,
        roles=tuple(
            replace(
                item,
                patterns=compact_patterns(item.patterns),
                exclude=compact_patterns(item.exclude),
            )
            for item in sorted(config.manifest.roles, key=lambda item: item.role.value)
        ),
        zones=tuple(
            replace(item, patterns=compact_patterns(item.patterns))
            for item in sorted(config.manifest.zones, key=lambda item: item.zone.value)
        ),
    )
    # include/force_include use Path.glob during discovery, unlike role matching.
    normalized = replace(config, manifest=manifest, exclude=compact_patterns(config.exclude))
    payload = {
        "configuration": normalized.digest(),
        "cache_enabled": config.cache_enabled,
        "cache_directory": config.cache_directory.value,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def simplify_configuration(
    root: Path, requested: ConfigPath | None, original: ProjectConfiguration
) -> str:
    raw, path = read_configuration_values(root, requested)
    is_tool = "taut" in table(raw.get("tool", {}), "tool")
    if not is_tool:
        raise PolicyConfigError("simplify requires a [tool.taut] configuration")
    section = deepcopy(table(table(raw["tool"], "tool")["taut"], "tool.taut"))
    expected = semantic_digest(original)
    levels = {rule: setting.level for rule, setting in original.policy.rules.items()}

    def load(value: dict[str, object]) -> ProjectConfiguration:
        document = parse_configuration_document({"tool": {"taut": value}}, path)
        return load_project_configuration(root, rule_levels=levels, document=document)

    candidates: list[tuple[str, ...]] = [(key,) for key in _DEFAULT_KEYS if key in section]
    for name in _DEFAULT_SECTIONS:
        values = table(section.get(name, {}), name)
        candidates.extend(
            (name, key)
            for key, value in values.items()
            if not isinstance(value, dict) and key not in {"assertions", "features"}
        )
    for keys in candidates:
        trial = deepcopy(section)
        target = trial if len(keys) == 1 else table(trial[keys[0]], keys[0])
        del target[keys[-1]]
        try:
            same = semantic_digest(load(trial)) == expected
        except (PolicyConfigError, ValueError):
            same = False
        if same:
            section = trial
    _compact_selectors(section)
    _group_effects(section)
    output = render_tool_configuration(section)
    parsed = table(table(tomllib.loads(output)["tool"], "tool")["taut"], "taut")
    if semantic_digest(load(parsed)) != expected:
        raise PolicyConfigError("simplification changed the effective policy; refusing proposal")
    return output


def _compact_selectors(section: dict[str, object]) -> None:
    def compact(values: dict[str, object], key: str) -> None:
        value = values.get(key)
        if isinstance(value, list) and all(
            isinstance(item, str) for item in cast(list[object], value)
        ):
            values[key] = list(compact_patterns(tuple(cast(list[str], value))))

    compact(section, "exclude")
    for name in ("roles", "zones"):
        values = table(section.get(name, {}), name)
        for key, value in values.items():
            if isinstance(value, dict):
                matcher = table(cast(object, value), key)
                compact(matcher, "include")
                compact(matcher, "exclude")
            else:
                compact(values, key)


def _group_effects(section: dict[str, object]) -> None:
    if "effects" not in section:
        return
    grouped: dict[tuple[tuple[str, ...], str], list[str]] = {}
    for entry in table_list(section["effects"], "effects"):
        effects = tuple(sorted(cast(list[str], entry["effects"])))
        access = cast(str, entry.get("access", "direct"))
        symbols = (
            [cast(str, entry["symbol"])] if "symbol" in entry else cast(list[str], entry["symbols"])
        )
        grouped.setdefault((effects, access), []).extend(symbols)
    section["effects"] = [
        {"symbols": list(dict.fromkeys(symbols)), "effects": list(effects), "access": access}
        for (effects, access), symbols in grouped.items()
    ]


def render_tool_configuration(section: dict[str, object]) -> str:
    """Render a normalized snippet; original file and comments are left untouched."""
    lines: list[str] = []

    def key_text(key: str) -> str:
        return key if re.fullmatch(r"[A-Za-z0-9_-]+", key) else json.dumps(key)

    def value_text(value: object) -> str:
        if isinstance(value, bool):
            return str(value).lower()
        if isinstance(value, str):
            return json.dumps(value, ensure_ascii=False)
        if isinstance(value, int):
            return str(value)
        if isinstance(value, list):
            return "[" + ", ".join(value_text(item) for item in cast(list[object], value)) + "]"
        if isinstance(value, dict):
            return (
                "{ "
                + ", ".join(
                    f"{key_text(key)} = {value_text(item)}"
                    for key, item in table(cast(object, value), "value").items()
                )
                + " }"
            )
        raise PolicyConfigError(f"cannot render configuration value: {type(value).__name__}")

    def emit(values: dict[str, object], prefix: str, *, array: bool = False) -> None:
        if not values and prefix != "tool.taut":
            return
        lines.extend(("", f"[[{prefix}]]" if array else f"[{prefix}]"))
        for key, value in values.items():
            original_value: object = value
            if isinstance(value, dict) or (
                isinstance(value, list) and value and isinstance(value[0], dict)
            ):
                continue
            rendered_key = key_text(key)
            rendered = value_text(original_value)
            if isinstance(value, list) and len(rendered_key) + len(rendered) > 95:
                lines.append(f"{rendered_key} = [")
                line = "   "
                for item in cast(list[object], value):
                    rendered_item = value_text(item) + ","
                    if len(line) > 3 and len(line) + len(rendered_item) + 1 > 100:
                        lines.append(line)
                        line = "   "
                    line += " " + rendered_item
                if len(line) > 3:
                    lines.append(line)
                lines.append("]")
            else:
                lines.append(f"{rendered_key} = {rendered}")
        for key, value in values.items():
            nested = f"{prefix}.{key_text(key)}"
            if isinstance(value, dict):
                emit(table(cast(object, value), key), nested)
            elif isinstance(value, list) and value and isinstance(value[0], dict):
                for item in table_list(cast(object, value), key):
                    emit(item, nested, array=True)

    emit(section, "tool.taut")
    return "\n".join(lines).lstrip() + "\n"
