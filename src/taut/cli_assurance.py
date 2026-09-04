from __future__ import annotations

import argparse
import json
from pathlib import Path

from taut import __version__
from taut.check_runtime import prepare_check_runtime
from taut.check_service import CheckRequest, run_check_request
from taut.configuration.assurance import BUILTIN_ASSURANCE_FEATURES
from taut.domain.ids import RuleId
from taut.domain.location import ConfigPath
from taut.loading.errors import PolicyConfigError
from taut.onboarding import (
    build_init_proposal,
    configuration_schema_payload,
    ensure_init_target_is_new,
    read_init_answers,
    write_init_configuration,
)
from taut.policy.rule import RuleDefinition
from taut.policy.rules import builtin_rule_registry
from taut.workspace import (
    TautWorkspace,
    discover_independent_projects,
    load_workspace,
    member_has_configuration,
    unlisted_workspace_projects,
    workspace_toml,
    write_workspace_manifest,
)


def run_init(namespace: argparse.Namespace) -> int:
    root = Path(namespace.project_root).resolve()
    if load_workspace(root) is not None:
        raise PolicyConfigError(
            "[tool.taut.workspace] already exists; use 'taut audit .' or 'taut check .'"
        )
    members = (
        discover_independent_projects(root)
        if Path(namespace.config) == Path("pyproject.toml")
        else ()
    )
    if len(members) > 1:
        return _run_workspace_init(root, members, namespace)
    ensure_init_target_is_new(root, Path(namespace.config))
    proposal = build_init_proposal(root, read_init_answers(namespace.answers))
    if namespace.format == "json":
        print(json.dumps(proposal.json_payload(), ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print(f"Taut init: {proposal.status}")
        print(f"Python 파일: {len(proposal.python_files)}")
        print(f"프로젝트 digest: {proposal.project_digest}")
        if proposal.questions:
            print("결정 필요:")
            for question in proposal.questions:
                print(f"- {question.id}: {question.prompt} (추천: {question.recommended})")
        else:
            print(proposal.toml, end="")
    if namespace.write:
        write_init_configuration(root, Path(namespace.config), proposal)
        if namespace.format == "text":
            print(f"설정 저장 완료: {namespace.config}")
    return 0 if proposal.status == "ready" else 2


def _run_workspace_init(root: Path, members: tuple[str, ...], namespace: argparse.Namespace) -> int:
    if namespace.answers is not None:
        raise PolicyConfigError(
            "workspace init does not accept one shared answers file; initialize each member"
        )
    missing = tuple(member for member in members if not member_has_configuration(root, member))
    ready = not missing
    if namespace.write and not ready:
        raise PolicyConfigError(
            "workspace members must each have [tool.taut] before writing the root manifest: "
            + ", ".join(missing)
        )
    proposal = workspace_toml(members)
    next_commands = [f"taut init {member} --format json" for member in missing]
    if missing:
        next_commands.append("taut init . --write")
    else:
        next_commands.extend(("taut audit .", "taut check ."))
    if namespace.format == "json":
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "workspace_ready" if ready else "workspace_needs_members",
                    "workspace": {
                        "members": members,
                        "unconfigured_members": missing,
                    },
                    "proposal": {"toml": proposal},
                    "next_commands": next_commands,
                },
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
            )
        )
    else:
        print("독립 Python 프로젝트를 발견했습니다: " + ", ".join(members))
        if missing:
            print("먼저 각 멤버를 설정하세요:")
            for command in next_commands[:-1]:
                print(f"- {command}")
        else:
            print(proposal, end="")
    if namespace.write:
        write_workspace_manifest(root, members)
        if namespace.format == "text":
            print("workspace 설정 저장 완료: pyproject.toml")
    return 0 if ready else 2


def run_audit(namespace: argparse.Namespace) -> int:
    root = Path(namespace.project_root).resolve()
    config_path = ConfigPath(namespace.config) if namespace.config is not None else None
    workspace = load_workspace(root) if config_path is None else None
    if workspace is not None:
        return _run_workspace_audit(workspace, namespace.format)
    result = run_check_request(
        CheckRequest(root, config_path, output_format="json"),
        runtime=prepare_check_runtime(root, config_path),
    )
    if result.report is None:
        raise PolicyConfigError("assurance report is unavailable")
    assurance = result.report.assurance
    complete = assurance.complete and not result.report.engine_issues
    if namespace.format == "json":
        check_payload = json.loads(result.stdout)
        payload = {
            "schema_version": 1,
            "engine_version": __version__,
            "assurance": check_payload["assurance"],
            "engine_issues": check_payload["engine_issues"],
            "exit": {
                "code": 0 if complete else 2,
                "reasons": [] if complete else ["strict assurance 미완료"],
            },
        }
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        for issue in assurance.issues:
            print(f"error: [assurance:{issue.code}] {issue.message} ({issue.subject})")
            print(f"  도움: {issue.remediation}")
        print("assurance 완료" if complete else f"assurance 미완료: {len(assurance.issues)}건")
    return 0 if complete else 2


def _run_workspace_audit(workspace: TautWorkspace, output_format: str) -> int:
    members: list[dict[str, object]] = []
    unlisted = unlisted_workspace_projects(workspace)
    complete = not unlisted
    for member in workspace.members:
        try:
            result = run_check_request(
                CheckRequest(member.root, output_format="json"),
                runtime=prepare_check_runtime(member.root),
            )
        except (PolicyConfigError, ValueError, OSError) as error:
            raise PolicyConfigError(f"workspace member {member.path}: {error}") from error
        if result.report is None:
            raise PolicyConfigError(f"workspace member {member.path}: assurance unavailable")
        payload = json.loads(result.stdout)
        member_complete = bool(result.report.assurance.complete and not result.report.engine_issues)
        complete = complete and member_complete
        members.append(
            {
                "path": member.path,
                "complete": member_complete,
                "assurance": payload["assurance"],
                "engine_issues": payload["engine_issues"],
            }
        )
    code = 0 if complete else 2
    if output_format == "json":
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "engine_version": __version__,
                    "kind": "workspace_audit",
                    "members": members,
                    "unlisted_projects": unlisted,
                    "exit": {
                        "code": code,
                        "reasons": [] if complete else ["workspace strict assurance 미완료"],
                    },
                },
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
            )
        )
    else:
        for item in members:
            state = "완료" if item["complete"] else "미완료"
            print(f"{item['path']}: assurance {state}")
        for project in unlisted:
            print(f"error: [assurance:WORKSPACE_MEMBER_UNLISTED] {project}")
        print("workspace assurance 완료" if complete else "workspace assurance 미완료")
    return code


def render_rule_json(selected: RuleDefinition) -> str:
    return json.dumps(
        {
            "id": selected.id.value,
            "level": selected.default_level.value,
            "title": selected.title,
            "target": selected.target.value,
            "zones": sorted(zone.value for zone in selected.applies_to_zones),
            "help": selected.help,
        },
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    )


def run_rules(namespace: argparse.Namespace) -> int:
    registry = builtin_rule_registry()
    selected = namespace.rule_id
    if selected is None:
        if namespace.format == "json":
            values = [json.loads(render_rule_json(item)) for item in registry.definitions.values()]
            print(json.dumps(values, ensure_ascii=False, sort_keys=True, indent=2))
            return 0
        for rule_id, item in registry.definitions.items():
            print(f"{rule_id.value}\t{item.default_level.value}\t{item.title}")
        return 0
    if not isinstance(selected, str):
        raise ValueError("rule_id must be a string")
    selected_definition = registry.definitions.get(RuleId(selected))
    if selected_definition is None:
        raise PolicyConfigError(f"unknown rule: {selected}")
    if namespace.format == "json":
        print(render_rule_json(selected_definition))
        return 0
    zones = ", ".join(sorted(zone.value for zone in selected_definition.applies_to_zones))
    print(f"{selected_definition.id.value} {selected_definition.title}")
    print(f"강도: {selected_definition.default_level.value}")
    print(f"적용 영역: {zones}")
    print(f"수정 방법: {selected_definition.help}")
    return 0


def run_config_schema(output_format: str) -> int:
    payload = configuration_schema_payload()
    if output_format == "json":
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print("Taut 설정 스키마 v5")
        print("strict=true: 규칙 위반과 assurance 완전성을 함께 강제")
        print("기능 상태: required 또는 absent")
        print("기능: " + ", ".join(BUILTIN_ASSURANCE_FEATURES))
    return 0
