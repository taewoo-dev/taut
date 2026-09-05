from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import cast

from taut.configuration.manifest import Role
from taut.configuration.path_patterns import compact_patterns
from taut.loading.config_values import integer
from taut.loading.errors import PolicyConfigError
from taut.onboarding_policy import validated_patterns
from taut.onboarding_role_evidence import InitRoleEvidence as InitRoleEvidence
from taut.onboarding_role_evidence import semantic_role_evidence, unique_role_evidence
from taut.project_observation import observe_path

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


@dataclass(frozen=True, order=True)
class InitRoleSelector:
    role: str
    include: tuple[str, ...]
    exclude: tuple[str, ...]
    reason: str
    priority: int = 0

    def matches(self, path: str) -> bool:
        return any(fnmatchcase(path, pattern) for pattern in self.include) and not any(
            fnmatchcase(path, pattern) for pattern in self.exclude
        )


@dataclass(frozen=True, order=True)
class InitRoleMatcher:
    role: str
    include: tuple[str, ...]
    exclude: tuple[str, ...]
    reasons: tuple[str, ...] = ()
    priority: int = 0


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


def answer_role_selectors(
    answers: dict[str, object] | None, paths: tuple[str, ...]
) -> tuple[InitRoleSelector, ...]:
    if answers is None:
        return ()
    raw = answers.get("role_selectors", [])
    if not isinstance(raw, list):
        raise PolicyConfigError("init answers.role_selectors must be an array")
    selectors: list[InitRoleSelector] = []
    for index, value in enumerate(cast(list[object], raw)):
        if not isinstance(value, dict):
            raise PolicyConfigError(f"init role_selectors[{index}] must be an object")
        raw_item = cast(dict[object, object], value)
        if not all(isinstance(key, str) for key in raw_item):
            raise PolicyConfigError(f"init role_selectors[{index}] must be an object")
        item = cast(dict[str, object], value)
        unknown = set(item).difference({"role", "include", "exclude", "reason", "priority"})
        if unknown:
            raise PolicyConfigError(
                f"unknown init role selector keys: {', '.join(sorted(unknown))}"
            )
        role = _validated_role(item.get("role"), f"role_selectors[{index}].role")
        include = validated_patterns(item.get("include"), f"role_selectors[{index}].include")
        exclude = validated_patterns(
            item.get("exclude", []), f"role_selectors[{index}].exclude", allow_empty=True
        )
        reason = item.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise PolicyConfigError("init role selector requires a non-empty reason")
        priority = integer(item.get("priority", 0), f"role_selectors[{index}].priority")
        if any(old.role == role and old.priority != priority for old in selectors):
            raise PolicyConfigError("init selectors for one role must have the same priority")
        selector = InitRoleSelector(role, include, exclude, reason.strip(), priority)
        if not any(selector.matches(path) for path in paths):
            raise PolicyConfigError(
                f"init role selector matches no discovered Python file: {include!r}"
            )
        selectors.append(selector)
    for path in paths:
        matching = [selector for selector in selectors if selector.matches(path)]
        highest = max((selector.priority for selector in matching), default=None)
        matches = {selector.role for selector in matching if selector.priority == highest}
        if len(matches) > 1:
            raise PolicyConfigError(
                f"init role selectors assign multiple roles to {path}: {', '.join(sorted(matches))}"
            )
    return tuple(sorted(set(selectors)))


def observe_roles(
    root: Path,
    paths: tuple[str, ...],
    aliases: dict[str, str],
    overrides: dict[str, str],
    selectors: tuple[InitRoleSelector, ...] = (),
) -> tuple[InitRoleObservation, ...]:
    return tuple(
        _observe_role(
            root,
            path,
            aliases,
            overrides.get(path),
            max(
                (item for item in selectors if item.matches(path)),
                key=lambda item: item.priority,
                default=None,
            ),
        )
        for path in paths
    )


def group_roles(
    observations: tuple[InitRoleObservation, ...],
) -> dict[str, tuple[str, ...]]:
    grouped: dict[str, list[str]] = {}
    for item in observations:
        grouped.setdefault(item.recommended, []).append(item.path)
    return {role: tuple(sorted(paths)) for role, paths in sorted(grouped.items())}


def synthesize_role_matchers(
    observations: tuple[InitRoleObservation, ...],
    selectors: tuple[InitRoleSelector, ...],
) -> tuple[InitRoleMatcher, ...]:
    includes: dict[str, set[str]] = {}
    excludes: dict[str, set[str]] = {}
    reasons: dict[str, set[str]] = {}
    for selector in selectors:
        includes.setdefault(selector.role, set()).update(selector.include)
        excludes.setdefault(selector.role, set()).update(selector.exclude)
        reasons.setdefault(selector.role, set()).add(selector.reason)
    for observation in observations:
        role_includes = includes.setdefault(observation.recommended, set())
        if any(fnmatchcase(observation.path, pattern) for pattern in role_includes):
            continue
        structural = _structural_patterns(observation)
        if structural:
            role_includes.update(structural)
        elif observation.confidence != "low":
            role_includes.add(observation.path)
    # Do not generate per-file exclusions to make a mixed directory pass. The
    # preflight reports conflicts; move/split code or review a stable selector.
    return tuple(
        InitRoleMatcher(
            role,
            compact_patterns(tuple(sorted(patterns))),
            compact_patterns(tuple(sorted(excludes.get(role, ())))),
            tuple(sorted(reasons.get(role, ()))),
            next((item.priority for item in selectors if item.role == role), 0),
        )
        for role, patterns in sorted(includes.items())
        if patterns
    )


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
    selector: InitRoleSelector | None = None,
) -> InitRoleObservation:
    if override is not None:
        explicit_evidence = (InitRoleEvidence(override, "answer", path, "explicit"),)
        return InitRoleObservation(
            path, override, (override,), "explicit", False, explicit_evidence
        )
    if selector is not None:
        evidence = (
            InitRoleEvidence(selector.role, "answer_selector", selector.reason, "explicit"),
        )
        return InitRoleObservation(
            path, selector.role, (selector.role,), "explicit", False, evidence
        )

    source_path = Path(path)
    parts = tuple(part.lower() for part in source_path.parts)
    directories = parts[:-1]
    stem = source_path.stem.lower()
    path_observation = observe_path(path)
    if path_observation.zone != "prod":
        return _single_role_observation(
            path, path_observation.zone, path_observation.kind, path_observation.evidence
        )

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
    signals.extend(semantic_role_evidence(content))
    signals = unique_role_evidence(signals)
    if not signals:
        fallback = InitRoleEvidence("application", "fallback", "no stronger role evidence", "low")
        return InitRoleObservation(path, "application", ("application",), "low", True, (fallback,))

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


def _structural_patterns(observation: InitRoleObservation) -> tuple[str, ...]:
    source = Path(observation.path)
    directories = tuple(part.lower() for part in source.parts[:-1])
    roots: list[str] = []
    for evidence in observation.evidence:
        if evidence.role != observation.recommended:
            continue
        if evidence.kind in {"directory", "custom_directory_alias"}:
            indexes = [index for index, part in enumerate(directories) if part == evidence.value]
            if indexes:
                roots.append(Path(*source.parts[: indexes[-1] + 1]).as_posix())
        elif evidence.kind in {"test_path", "migration_path", "script_path"}:
            markers = {
                "test_path": {"tests"},
                "migration_path": {"migrations", "alembic"},
                "script_path": {"scripts"},
            }[evidence.kind]
            indexes = [index for index, part in enumerate(directories) if part in markers]
            if indexes:
                roots.append(Path(*source.parts[: indexes[0] + 1]).as_posix())
    if not roots:
        for evidence in observation.evidence:
            if evidence.kind == "filename_suffix" and evidence.role == observation.recommended:
                parent = source.parent.as_posix()
                prefix = "" if parent == "." else f"{parent}/"
                return (f"{prefix}*{evidence.value}.py", f"{prefix}*{evidence.value}.pyi")
        return ()
    root = min(roots, key=lambda item: (len(Path(item).parts), item))
    return (
        f"{root}/*.py",
        f"{root}/*.pyi",
    )
