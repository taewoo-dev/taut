"""Reviewable role observations and role-related init answers."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from taut.configuration.manifest import Role
from taut.loading.errors import PolicyConfigError

_ROLE_ALIAS_NAME = re.compile(r"^[a-z][a-z0-9_-]*$")
_CONFIDENCE_SCORE = {"low": 1, "medium": 2, "high": 3, "explicit": 4}
_EVIDENCE_PRIORITY = {
    "answer": 50,
    "custom_directory_alias": 40,
    "directory": 40,
    "api_version_path": 40,
    "filename": 35,
    "inherits": 30,
    "constructs": 30,
    "filename_suffix": 20,
    "fallback": 10,
}
_ROLE_ORDER = (
    "test",
    "migration",
    "script",
    "router",
    "dto",
    "snapshot",
    "exception",
    "enum",
    "schema",
    "model",
    "repository",
    "validator",
    "aggregator",
    "adapter",
    "service",
    "configuration",
    "bootstrap",
    "application",
)
_ROLE_PRIORITY = {role: index for index, role in enumerate(_ROLE_ORDER)}
_DIRECTORY_ROLE_ALIASES = {
    "adapter": "adapter",
    "adapters": "adapter",
    "aggregator": "aggregator",
    "aggregators": "aggregator",
    "client": "adapter",
    "clients": "adapter",
    "config": "configuration",
    "configuration": "configuration",
    "dto": "dto",
    "dtos": "dto",
    "enum": "enum",
    "enums": "enum",
    "error": "exception",
    "errors": "exception",
    "exception": "exception",
    "exceptions": "exception",
    "model": "model",
    "models": "model",
    "repo": "repository",
    "repos": "repository",
    "repositories": "repository",
    "repository": "repository",
    "router": "router",
    "routers": "router",
    "routes": "router",
    "schema": "schema",
    "schemas": "schema",
    "service": "service",
    "services": "service",
    "settings": "configuration",
    "snapshot": "snapshot",
    "snapshots": "snapshot",
    "validator": "validator",
    "validators": "validator",
}
_FILE_ROLE_ALIASES = {
    **_DIRECTORY_ROLE_ALIASES,
    "api": "router",
    "bootstrap": "bootstrap",
    "container": "bootstrap",
    "main": "bootstrap",
}
_FILE_ROLE_SUFFIXES = {
    "_adapter": "adapter",
    "_aggregator": "aggregator",
    "_client": "adapter",
    "_dto": "dto",
    "_enum": "enum",
    "_error": "exception",
    "_exception": "exception",
    "_model": "model",
    "_repository": "repository",
    "_router": "router",
    "_schema": "schema",
    "_service": "service",
    "_snapshot": "snapshot",
    "_validator": "validator",
}


@dataclass(frozen=True)
class InitRoleEvidence:
    role: str
    kind: str
    value: str
    confidence: str

    def json_payload(self) -> dict[str, str]:
        return {
            "role": self.role,
            "kind": self.kind,
            "value": self.value,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class InitRoleObservation:
    path: str
    recommended: str
    candidates: tuple[str, ...]
    confidence: str
    requires_review: bool
    evidence: tuple[InitRoleEvidence, ...]

    def json_payload(self) -> dict[str, object]:
        return {
            "path": self.path,
            "recommended": self.recommended,
            "candidates": self.candidates,
            "confidence": self.confidence,
            "requires_review": self.requires_review,
            "evidence": [item.json_payload() for item in self.evidence],
        }


def answer_role_aliases(answers: dict[str, object] | None) -> dict[str, str]:
    if answers is None:
        return {}
    raw = answers.get("role_aliases", {})
    if not isinstance(raw, dict):
        raise PolicyConfigError("init answers.role_aliases must be an object")
    result: dict[str, str] = {}
    for alias, value in cast(dict[object, object], raw).items():
        if not isinstance(alias, str) or not _ROLE_ALIAS_NAME.fullmatch(alias):
            raise PolicyConfigError(f"invalid init role alias: {alias!r}")
        role = _validated_role(value, f"role_aliases.{alias}")
        builtin = _DIRECTORY_ROLE_ALIASES.get(alias)
        if builtin is not None and builtin != role:
            raise PolicyConfigError(
                f"init role alias cannot redefine built-in directory {alias!r}: {builtin}"
            )
        result[alias] = role
    return result


def answer_roles(answers: dict[str, object] | None, paths: tuple[str, ...]) -> dict[str, str]:
    if answers is None:
        return {}
    raw = answers.get("roles", {})
    if not isinstance(raw, dict):
        raise PolicyConfigError("init answers.roles must be an object")
    known_paths = set(paths)
    result: dict[str, str] = {}
    for path, value in cast(dict[object, object], raw).items():
        if not isinstance(path, str) or path not in known_paths:
            raise PolicyConfigError(
                f"init role override does not match a discovered Python file: {path!r}"
            )
        result[path] = _validated_role(value, f"roles.{path}")
    return result


def observe_roles(
    root: Path,
    paths: tuple[str, ...],
    aliases: dict[str, str],
    overrides: dict[str, str],
) -> tuple[InitRoleObservation, ...]:
    return tuple(_observe_role(root, path, aliases, overrides.get(path)) for path in paths)


def group_roles(
    observations: tuple[InitRoleObservation, ...],
) -> dict[str, tuple[str, ...]]:
    grouped: dict[str, list[str]] = {}
    for item in observations:
        grouped.setdefault(item.recommended, []).append(item.path)
    return {role: tuple(sorted(paths)) for role, paths in sorted(grouped.items())}


def _validated_role(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise PolicyConfigError(f"init answers.{field} must be a role name")
    try:
        return Role(value).value
    except ValueError as error:
        raise PolicyConfigError(f"invalid init role for {field}: {value!r}") from error


def _observe_role(
    root: Path,
    path: str,
    aliases: dict[str, str],
    override: str | None,
) -> InitRoleObservation:
    if override is not None:
        explicit_evidence = (InitRoleEvidence(override, "answer", path, "explicit"),)
        return InitRoleObservation(
            path, override, (override,), "explicit", False, explicit_evidence
        )

    source_path = Path(path)
    parts = tuple(part.lower() for part in source_path.parts)
    directories = parts[:-1]
    stem = source_path.stem.lower()
    if "tests" in directories or stem.startswith("test_") or stem == "conftest":
        return _single_role_observation(path, "test", "test_path", path)
    if "migrations" in directories or "alembic" in directories:
        return _single_role_observation(path, "migration", "migration_path", path)
    if "scripts" in directories:
        return _single_role_observation(path, "script", "script_path", path)

    signals: list[InitRoleEvidence] = []
    combined_aliases = {**_DIRECTORY_ROLE_ALIASES, **aliases}
    for directory in directories:
        role = combined_aliases.get(directory)
        if role is not None:
            kind = "custom_directory_alias" if directory in aliases else "directory"
            signals.append(InitRoleEvidence(role, kind, directory, "high"))
    if any(
        part == "api" and index + 1 < len(parts) and re.fullmatch(r"v[0-9]+", parts[index + 1])
        for index, part in enumerate(directories)
    ):
        signals.append(InitRoleEvidence("router", "api_version_path", path, "high"))
    if role := _FILE_ROLE_ALIASES.get(stem):
        signals.append(InitRoleEvidence(role, "filename", source_path.name, "high"))
    for suffix, role in _FILE_ROLE_SUFFIXES.items():
        if stem.endswith(suffix):
            signals.append(InitRoleEvidence(role, "filename_suffix", suffix, "medium"))
    try:
        content = (root / path).read_text(errors="replace")
    except OSError:
        content = ""
    signals.extend(_semantic_role_evidence(content))
    signals = _unique_role_evidence(signals)
    if not signals:
        fallback = InitRoleEvidence("application", "fallback", "no stronger role evidence", "low")
        return InitRoleObservation(path, "application", ("application",), "low", False, (fallback,))

    scores: dict[str, tuple[int, int]] = {}
    for item in signals:
        score = (_CONFIDENCE_SCORE[item.confidence], _EVIDENCE_PRIORITY[item.kind])
        scores[item.role] = max(scores.get(item.role, (0, 0)), score)
    candidates = tuple(
        sorted(
            scores,
            key=lambda role: (
                -scores[role][0],
                -scores[role][1],
                _ROLE_PRIORITY.get(role, len(_ROLE_ORDER)),
                role,
            ),
        )
    )
    recommended = candidates[0]
    confidence_score = scores[recommended][0]
    confidence = next(
        name for name, score in _CONFIDENCE_SCORE.items() if score == confidence_score
    )
    return InitRoleObservation(
        path,
        recommended,
        candidates,
        confidence,
        len(candidates) > 1,
        tuple(signals),
    )


def _single_role_observation(path: str, role: str, kind: str, value: str) -> InitRoleObservation:
    evidence = (InitRoleEvidence(role, kind, value, "high"),)
    return InitRoleObservation(path, role, (role,), "high", False, evidence)


def _semantic_role_evidence(content: str) -> list[InitRoleEvidence]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".", 1)[0]] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"

    result: list[InitRoleEvidence] = []
    for descendant in ast.walk(tree):
        if isinstance(descendant, ast.ClassDef):
            for base in descendant.bases:
                symbol = _resolved_expression_name(base, aliases)
                if symbol == "tortoise.models.Model":
                    result.append(InitRoleEvidence("model", "inherits", symbol, "high"))
                elif symbol in {"pydantic.BaseModel", "pydantic.main.BaseModel"}:
                    result.append(InitRoleEvidence("schema", "inherits", symbol, "high"))
        elif isinstance(descendant, ast.Call):
            symbol = _resolved_expression_name(descendant.func, aliases)
            if symbol in {"fastapi.APIRouter", "fastapi.routing.APIRouter"}:
                result.append(InitRoleEvidence("router", "constructs", symbol, "high"))
    return result


def _resolved_expression_name(node: ast.expr, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _resolved_expression_name(node.value, aliases)
        return f"{parent}.{node.attr}" if parent is not None else None
    return None


def _unique_role_evidence(values: list[InitRoleEvidence]) -> list[InitRoleEvidence]:
    seen: set[tuple[str, str, str, str]] = set()
    result: list[InitRoleEvidence] = []
    for item in values:
        key = (item.role, item.kind, item.value, item.confidence)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result
