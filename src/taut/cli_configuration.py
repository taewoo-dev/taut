"""Read-only configuration inspection and simplification commands."""

from __future__ import annotations

import json
from pathlib import Path

from taut.check_runtime import prepare_check_runtime
from taut.cli_workspace import configuration_payload
from taut.domain.location import ConfigPath
from taut.loading.config_simplification import simplify_configuration
from taut.loading.configuration_document import configuration_origins
from taut.loading.errors import PolicyConfigError
from taut.loading.source_discovery import discover_sources


def run_simplify(root: Path, config_path: ConfigPath | None) -> int:
    config = prepare_check_runtime(root, config_path).config
    print(simplify_configuration(root, config_path, config), end="")
    return 0


def run_explain(
    root: Path, config_path: ConfigPath | None, output_format: str, path: str | None = None
) -> int:
    config = prepare_check_runtime(root, config_path).config
    payload = configuration_payload(config)
    payload["origins"] = configuration_origins(root, config_path)
    payload["default_origin"] = "Taut built-in defaults (values not explicitly configured)"
    exit_code = 0
    if path is not None:
        try:
            relative = (root / path).resolve().relative_to(root).as_posix()
        except ValueError as error:
            raise PolicyConfigError("--path must be inside the selected project root") from error
        selected = config.manifest.role_for_path(relative)
        in_scope = any(
            source.path.value == relative for source in discover_sources(root, config).sources
        )
        payload["path"] = {
            "path": relative,
            "exists": (root / relative).is_file(),
            "in_scope": in_scope,
            "role": selected.role.value if selected else None,
            "priority": selected.priority if selected else None,
            "matching_selectors": [
                {
                    "role": matcher.role.value,
                    "priority": matcher.priority,
                    "patterns": matcher.patterns,
                }
                for matcher in config.manifest.roles
                if matcher.matches(relative)
            ],
            "allowed_imports": sorted(
                role.value for role in config.policy.allowed_imports.get(selected.role, frozenset())
            )
            if selected
            else [],
            "remediation": (
                "Place code in a declared role path and align its responsibilities. "
                "Change conventions only when introducing a new architecture."
                if selected is None
                else "Roles follow path conventions. Use check to verify code compliance."
            ),
        }
        exit_code = 0 if selected is not None and in_scope else 2
    if output_format == "json":
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print(f"Schema: v{config.schema_version}")
        print(f"Rule packs: {', '.join(config.packs)}")
        print(f"Analysis providers: {', '.join(config.providers) or '(none)'}")
        print(f"Default zone: {config.manifest.default_zone.value}")
        print(f"Maximum file length: {config.policy.default_max_lines}")
        print(f"Configuration digest: {config.digest()}")
        for key in (
            "path",
            "roles",
            "include",
            "exclude",
            "force_include",
            "zones",
            "effects",
            "assurance",
            "effective_policy",
            "origins",
            "default_origin",
        ):
            if key in payload:
                rendered = json.dumps(payload[key], ensure_ascii=False, sort_keys=True, indent=2)
                print(f"{key}: {rendered}")
    return exit_code
