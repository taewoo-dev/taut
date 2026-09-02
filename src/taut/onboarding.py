from __future__ import annotations

import ast
import hashlib
import json
import os
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import cast

from taut.analysis.module_identity import absolute_import_base, resolve_internal_import
from taut.configuration.assurance import BUILTIN_ASSURANCE_FEATURES
from taut.domain.ids import ModuleId
from taut.loading.errors import PolicyConfigError
from taut.onboarding_detection import detect_features, detect_providers, observed_response_mappers
from taut.onboarding_policy import (
    InitPolicyAnswers,
    answer_policy,
    effective_zones,
    render_policy_lines,
)
from taut.onboarding_questions import InitQuestion, build_init_questions
from taut.onboarding_roles import (
    InitRoleObservation,
    answer_role_aliases,
    answer_roles,
    group_roles,
    observe_roles,
)
from taut.onboarding_scope import (
    InitSourceScope,
    module_details,
    observe_source_scope,
    selected_source_roots,
)
from taut.onboarding_size import InitSizePolicy, render_size_lines, size_policy

INIT_CONTRACT_VERSION = 5


@dataclass(frozen=True)
class InitProposal:
    project_digest: str
    status: str
    python_files: tuple[str, ...]
    detected_features: tuple[str, ...]
    providers: tuple[str, ...]
    source_scope: InitSourceScope
    source_roots: tuple[str, ...]
    role_observations: tuple[InitRoleObservation, ...]
    observed_response_mappers: tuple[str, ...]
    size: InitSizePolicy
    questions: tuple[InitQuestion, ...]
    toml: str

    def json_payload(self) -> dict[str, object]:
        return {
            "schema_version": INIT_CONTRACT_VERSION,
            "status": self.status,
            "project_digest": self.project_digest,
            "discovered": {
                "python_files": self.python_files,
                "features": self.detected_features,
                "providers": self.providers,
                "source_scope": {
                    **self.source_scope.json_payload(),
                    "selected_source_roots": self.source_roots,
                },
                "roles": [item.json_payload() for item in self.role_observations],
                "response_mappers": self.observed_response_mappers,
                "size": self.size.json_payload(),
            },
            "proposal": {"toml": self.toml},
            "questions": [
                {
                    "id": item.id,
                    "prompt": item.prompt,
                    "choices": item.choices,
                    "recommended": item.recommended,
                    "evidence": item.evidence,
                }
                for item in self.questions
            ],
            "next_commands": [
                "taut init . --format json",
                "taut init . --answers answers.json --write",
                "taut audit .",
                "taut check .",
            ],
        }


def build_init_proposal(project_root: Path, answers: dict[str, object] | None) -> InitProposal:
    root = project_root.resolve()
    discovered_paths = _python_files(root)
    source_scope = observe_source_scope(root, discovered_paths)
    digest = _project_digest(root, discovered_paths, source_scope.metadata_files)
    _validate_answer_keys(answers)
    _validate_answer_version(answers)
    answer_digest = answers.get("project_digest") if answers else None
    if answers and answer_digest != digest:
        raise PolicyConfigError(
            "init answers are stale: project_digest differs; run 'taut init . --format json' again"
        )
    policy_answers = answer_policy(answers)
    paths = _analysis_paths(discovered_paths, policy_answers)
    evidence = detect_features(root, paths)
    detected = tuple(name for name in BUILTIN_ASSURANCE_FEATURES if evidence[name])
    providers = detect_providers(root, paths)
    source_roots, source_scope_resolved = selected_source_roots(root, paths, source_scope, answers)
    feature_answers = _answer_features(answers)
    role_aliases = answer_role_aliases(answers)
    role_overrides = answer_roles(answers, paths)
    accepted = _answer_architecture_acceptance(answers)
    role_observations = observe_roles(root, paths, role_aliases, role_overrides)
    response_mappers = observed_response_mappers(root, paths)
    roles = group_roles(role_observations)
    size = size_policy(root, role_observations, answers)
    expectations = {
        name: feature_answers.get(name, "required" if evidence[name] else "absent")
        for name in BUILTIN_ASSURANCE_FEATURES
    }
    zones = effective_zones(paths, policy_answers)
    questions = build_init_questions(
        paths=paths,
        source_scope=source_scope,
        source_scope_resolved=source_scope_resolved,
        architecture_accepted=accepted,
        role_observations=role_observations,
        role_overrides=role_overrides,
        feature_answers=feature_answers,
        expectations=expectations,
        feature_evidence=evidence,
        policy=policy_answers,
        observed_response_mappers=response_mappers,
        size=size,
    )
    status = "ready" if not questions else "needs_input"
    return InitProposal(
        project_digest=digest,
        status=status,
        python_files=discovered_paths,
        detected_features=detected,
        providers=providers,
        source_scope=source_scope,
        source_roots=source_roots,
        role_observations=role_observations,
        observed_response_mappers=response_mappers,
        size=size,
        questions=questions,
        toml=_render_configuration(
            root,
            paths,
            expectations,
            roles,
            source_roots,
            zones,
            policy_answers,
            size,
            providers,
        ),
    )


def read_init_answers(path: str | None) -> dict[str, object] | None:
    if path is None:
        return None
    try:
        text = sys.stdin.read() if path == "-" else Path(path).read_text()
        value: object = json.loads(text)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PolicyConfigError(f"cannot read init answers: {error}") from error
    if not isinstance(value, dict):
        raise PolicyConfigError("init answers must be a JSON object")
    mapping = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in mapping):
        raise PolicyConfigError("init answers must be a JSON object")
    return {cast(str, key): item for key, item in mapping.items()}


def ensure_init_target_is_new(project_root: Path, config_path: Path) -> None:
    """Refuse init for an existing Taut configuration, even in preview mode."""
    root = project_root.resolve()
    target = config_path if config_path.is_absolute() else root / config_path
    legacy = root / ".policy" / "policy.toml"
    if target.name == "pyproject.toml" and legacy.is_file():
        raise PolicyConfigError(
            ".policy/policy.toml already exists; use 'taut audit .' or 'taut config migrate .'"
        )
    if not target.exists():
        return
    if target.name != "pyproject.toml":
        raise PolicyConfigError(
            f"configuration already exists: {target}; use 'taut audit .' or 'taut config migrate .'"
        )
    try:
        raw = tomllib.loads(target.read_text())
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise PolicyConfigError(f"cannot read pyproject.toml: {error}") from error
    tool = raw.get("tool", {})
    if isinstance(tool, dict) and "taut" in tool:
        raise PolicyConfigError(
            "[tool.taut] already exists; use 'taut audit .' or 'taut config migrate .'"
        )


def write_init_configuration(project_root: Path, config_path: Path, proposal: InitProposal) -> None:
    if proposal.status != "ready":
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
        addition = proposal.toml
        content = existing.rstrip() + ("\n\n" if existing.strip() else "") + addition
    else:
        if target.exists():
            raise PolicyConfigError(f"configuration already exists: {target}")
        content = proposal.toml.replace("tool.taut.", "").replace("[tool.taut]", "")
        content = content.lstrip()
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


def configuration_schema_payload() -> dict[str, object]:
    return {
        "schema_version": 5,
        "strict": {
            "type": "boolean",
            "default": True,
            "description": "Enforce findings and project assurance completeness.",
        },
        "transaction": {
            "owner_roles": "roles allowed to create or finish transactions",
            "session_providers": "fully qualified context-manager call symbols",
            "boundary_decorators": "fully qualified transaction decorator symbols",
            "provider_item_types": "optional provider-symbol to yielded-type mapping",
        },
        "code_conventions": {
            "response_mapper_name": "single project-standard Response mapper method",
            "dto_base_symbols": "fully qualified immutable DTO base classes",
            "exception_code_argument_names": "accepted constructor keyword names",
            "exception_code_field_names": "accepted class field names",
            "test_http_fixture_symbols": "approved pytest fixture symbols",
        },
        "size": {
            "default_max_lines": "positive project-wide fallback",
            "role_max_lines": "positive per-role limits no larger than the fallback",
            "init_answer": "accept observed recommendation or provide explicit values",
        },
        "assurance": {
            "features": {
                "required_keys": BUILTIN_ASSURANCE_FEATURES,
                "values": ("required", "absent"),
            },
            "max_approvals": {"type": "integer", "minimum": 0, "default": 0},
            "max_inline_ignores": {"type": "integer", "minimum": 0, "default": 0},
            "assertions": {
                "fields": ("domain", "kind", "target", "state", "reason"),
                "state": "not_applicable",
            },
        },
        "exclusions": {
            "fields": ("patterns", "reason"),
            "description": "Reasoned Python source exclusions; stale patterns fail assurance.",
        },
    }


def _answer_features(answers: dict[str, object] | None) -> dict[str, str]:
    if answers is None:
        return {}
    raw = answers.get("features", {})
    if not isinstance(raw, dict):
        raise PolicyConfigError("init answers.features must be an object")
    feature_values = cast(dict[object, object], raw)
    result: dict[str, str] = {}
    for name, value in feature_values.items():
        if (
            not isinstance(name, str)
            or not isinstance(value, str)
            or name not in BUILTIN_ASSURANCE_FEATURES
            or value not in {"required", "absent"}
        ):
            raise PolicyConfigError(f"invalid init feature answer: {name}={value}")
        result[name] = value
    return result


def _validate_answer_keys(answers: dict[str, object] | None) -> None:
    if answers is None:
        return
    unknown = set(answers).difference(
        {
            "project_digest",
            "schema_version",
            "accept_observed_architecture",
            "accept_observed_source_scope",
            "source_roots",
            "features",
            "roles",
            "role_aliases",
            "zones",
            "exclusions",
            "policy",
            "size",
        }
    )
    if unknown:
        raise PolicyConfigError(f"unknown init answer keys: {', '.join(sorted(unknown))}")


def _validate_answer_version(answers: dict[str, object] | None) -> None:
    if answers is None:
        return
    version = answers.get("schema_version")
    if version != INIT_CONTRACT_VERSION:
        raise PolicyConfigError(
            f"init answers.schema_version must be {INIT_CONTRACT_VERSION}; regenerate answers"
        )


def _answer_architecture_acceptance(answers: dict[str, object] | None) -> bool:
    if answers is None or "accept_observed_architecture" not in answers:
        return False
    value = answers["accept_observed_architecture"]
    if not isinstance(value, bool):
        raise PolicyConfigError("init answers.accept_observed_architecture must be a boolean")
    return value


def _python_files(root: Path) -> tuple[str, ...]:
    ignored = {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".research",
        ".ruff_cache",
        ".taut_cache",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "venv",
    }
    return tuple(
        sorted(
            path.relative_to(root).as_posix()
            for path in root.rglob("*.py")
            if path.is_file() and not any(part in ignored for part in path.parts)
        )
    )


def _analysis_paths(paths: tuple[str, ...], policy_answers: InitPolicyAnswers) -> tuple[str, ...]:
    excluded = tuple(
        pattern for exclusion in policy_answers.exclusions for pattern in exclusion.patterns
    )
    return tuple(
        path for path in paths if not any(fnmatchcase(path, pattern) for pattern in excluded)
    )


def _project_digest(root: Path, paths: tuple[str, ...], metadata_paths: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    for path in tuple(sorted(set(paths).union(metadata_paths))):
        digest.update(path.encode())
        digest.update(b"\0")
        digest.update((root / path).read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _render_configuration(
    root: Path,
    paths: tuple[str, ...],
    expectations: dict[str, str],
    roles: dict[str, tuple[str, ...]],
    source_roots: tuple[str, ...],
    zones: dict[str, tuple[str, ...]],
    policy_answers: InitPolicyAnswers,
    size: InitSizePolicy,
    providers: tuple[str, ...],
) -> str:
    allow = _observed_allow_graph(root, paths, roles, source_roots)
    lines = [
        "[tool.taut]",
        "schema_version = 5",
        'packs = ["taut.backend"]',
        f"providers = {_toml_array(providers)}",
        "strict = true",
        f"max_lines = {size.default_max_lines}",
        'include = ["*.py", "**/*.py"]',
        f"exclude = {_toml_array(_exclude_patterns(policy_answers))}",
        f"source_roots = {_toml_array(source_roots)}",
        "",
        "[tool.taut.roles]",
    ]
    for role, role_paths in sorted(roles.items()):
        lines.append(f"{role} = {_toml_array(role_paths)}")
    lines.extend(("", "[tool.taut.allow]"))
    for role, targets in sorted(allow.items()):
        lines.append(f"{role} = {_toml_array(tuple(sorted(targets)))}")
    if zones:
        lines.extend(("", "[tool.taut.zones]"))
        for name, items in sorted(zones.items()):
            lines.append(f"{name} = {_toml_array(items)}")
    lines.extend(render_policy_lines(policy_answers))
    lines.extend(render_size_lines(size))
    lines.extend(("", "[tool.taut.assurance]", "max_approvals = 0", "max_inline_ignores = 0"))
    lines.extend(("", "[tool.taut.assurance.features]"))
    lines.extend(f'{name} = "{expectations[name]}"' for name in BUILTIN_ASSURANCE_FEATURES)
    return "\n".join(lines) + "\n"


def _observed_allow_graph(
    root: Path,
    paths: tuple[str, ...],
    roles: dict[str, tuple[str, ...]],
    source_roots: tuple[str, ...],
) -> dict[str, set[str]]:
    role_by_module: dict[ModuleId, str] = {}
    for role, role_paths in roles.items():
        for path in role_paths:
            try:
                module = module_details(path, source_roots)[0]
            except ValueError:
                continue
            role_by_module[module] = role
    modules_by_name = {module.value: module for module in role_by_module}
    result = {role: {role} for role in roles}
    for path in paths:
        try:
            source_module, is_package = module_details(path, source_roots)
        except ValueError:
            continue
        source_role = role_by_module.get(source_module)
        if source_role is None:
            continue
        try:
            tree = ast.parse((root / path).read_text())
        except (OSError, UnicodeError, SyntaxError):
            continue
        imported: set[ModuleId] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    target = resolve_internal_import(alias.name, alias.name, modules_by_name)
                    if target is not None:
                        imported.add(target)
            elif isinstance(node, ast.ImportFrom):
                base = absolute_import_base(source_module, is_package, node.module, node.level)
                for alias in node.names:
                    imported_name = f"{base}.{alias.name}" if base and alias.name != "*" else base
                    target = resolve_internal_import(imported_name, base, modules_by_name)
                    if target is not None:
                        imported.add(target)
        for target_module in imported:
            target_role = role_by_module[target_module]
            if target_role != source_role:
                result[source_role].add(target_role)
    return result


def _toml_array(values: tuple[str, ...]) -> str:
    return "[" + ", ".join(json.dumps(value) for value in values) + "]"


def _exclude_patterns(policy_answers: InitPolicyAnswers) -> tuple[str, ...]:
    defaults = (".venv/**", "**/__pycache__/**", "build/**", "dist/**")
    additions = tuple(
        pattern for exclusion in policy_answers.exclusions for pattern in exclusion.patterns
    )
    return tuple(dict.fromkeys((*defaults, *additions)))
