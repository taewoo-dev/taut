"""CLI composition for explicit multi-project workspaces."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

from taut import __version__
from taut.check_runtime import prepare_check_runtime
from taut.check_service import CheckResult
from taut.configuration.model import ProjectConfiguration
from taut.domain.location import ConfigPath
from taut.loading.errors import PolicyConfigError
from taut.workspace import TautWorkspace, unlisted_workspace_projects


@dataclass(frozen=True)
class CheckOptions:
    project_root: Path
    config_path: ConfigPath | None
    output_format: str
    show_inactive: bool
    verbose: bool
    color: str
    width: int | None
    no_cache: bool = False
    cache_dir: Path | None = None
    daemon_mode: str = "never"


def run_workspace_check(
    options: CheckOptions,
    workspace: TautWorkspace,
    execute: Callable[[CheckOptions], CheckResult],
) -> int:
    results: list[tuple[str, CheckResult]] = []
    unlisted = unlisted_workspace_projects(workspace)
    for member in workspace.members:
        member_cache = options.cache_dir / member.path if options.cache_dir is not None else None
        member_options = replace(options, project_root=member.root, cache_dir=member_cache)
        try:
            result = execute(member_options)
        except (PolicyConfigError, ValueError, OSError) as error:
            raise PolicyConfigError(f"workspace member {member.path}: {error}") from error
        results.append((member.path, result))
    exit_code = max((2 if unlisted else 0), *(result.exit_code for _, result in results))
    if options.output_format == "json":
        payload = {
            "schema_version": 1,
            "engine_version": __version__,
            "kind": "workspace",
            "members": [
                {
                    "path": path,
                    "exit_code": result.exit_code,
                    "report": json.loads(result.stdout),
                }
                for path, result in results
            ],
            "unlisted_projects": unlisted,
            "exit": {
                "code": exit_code,
                "reasons": [
                    f"{path}: exit {result.exit_code}"
                    for path, result in results
                    if result.exit_code != 0
                ]
                + [f"unlisted workspace project: {path}" for path in unlisted],
            },
        }
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        sections = [f"== {path} ==\n{result.stdout.decode().rstrip()}" for path, result in results]
        sections.append(
            "workspace 검사 완료: "
            + ", ".join(f"{path}=exit {result.exit_code}" for path, result in results)
        )
        if unlisted:
            sections.append("unlisted workspace projects: " + ", ".join(unlisted))
        print("\n\n".join(sections))
    for path, result in results:
        if result.stderr:
            sys.stderr.write(f"[{path}]\n{result.stderr.decode()}")
    return exit_code


def run_workspace_config(workspace: TautWorkspace, command: str, output_format: str) -> int:
    if command == "migrate":
        raise PolicyConfigError(
            "migrate workspace members individually; the workspace manifest has its own schema"
        )
    loaded_members: list[tuple[str, ProjectConfiguration]] = []
    for member in workspace.members:
        try:
            loaded_members.append((member.path, prepare_check_runtime(member.root).config))
        except (PolicyConfigError, ValueError, OSError) as error:
            raise PolicyConfigError(f"workspace member {member.path}: {error}") from error
    if command == "validate":
        unlisted = unlisted_workspace_projects(workspace)
        if unlisted:
            raise PolicyConfigError(
                "workspace projects missing from tool.taut.workspace.members: "
                + ", ".join(unlisted)
            )
        for path, configured in loaded_members:
            print(f"설정 정상: {path}/{configured.manifest.source.path} ({configured.digest()})")
        return 0
    if command != "explain":
        raise PolicyConfigError(f"unsupported workspace config command: {command}")
    members = [
        {"path": path, **configuration_payload(configured)} for path, configured in loaded_members
    ]
    payload = {"workspace_schema_version": 1, "members": members}
    if output_format == "json":
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        for config_member in members:
            print(
                f"{config_member['path']}: 스키마 v{config_member['schema_version']}, "
                f"digest {config_member['configuration_digest']}"
            )
    return 0


def configuration_payload(config: ProjectConfiguration) -> dict[str, object]:
    return {
        "schema_version": config.schema_version,
        "configuration_digest": config.digest(),
        "packs": config.packs,
        "providers": config.providers,
        "source_roots": tuple(path.value for path in config.source_roots),
        "roles": tuple(
            {
                "name": role.role.value,
                "include": role.patterns,
                "exclude": role.exclude,
                "priority": role.priority,
            }
            for role in config.manifest.roles
        ),
        "default_zone": config.manifest.default_zone.value,
        "default_max_lines": config.policy.default_max_lines,
    }
