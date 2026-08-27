from __future__ import annotations

import ast
import hashlib
import json
import os
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from taut.configuration.assurance import BUILTIN_ASSURANCE_FEATURES
from taut.loading.errors import PolicyConfigError


@dataclass(frozen=True)
class InitQuestion:
    id: str
    prompt: str
    choices: tuple[str, ...]
    recommended: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class InitProposal:
    project_digest: str
    status: str
    python_files: tuple[str, ...]
    detected_features: tuple[str, ...]
    questions: tuple[InitQuestion, ...]
    toml: str

    def json_payload(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "status": self.status,
            "project_digest": self.project_digest,
            "discovered": {
                "python_files": self.python_files,
                "features": self.detected_features,
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
    paths = _python_files(root)
    digest = _project_digest(root, paths)
    evidence = _detect_features(root, paths)
    detected = tuple(name for name in BUILTIN_ASSURANCE_FEATURES if evidence[name])
    feature_answers = _answer_features(answers)
    accepted = bool(answers and answers.get("accept_observed_architecture") is True)
    answer_digest = answers.get("project_digest") if answers else None
    if answers and answer_digest != digest:
        raise PolicyConfigError(
            "init answers are stale: project_digest differs; run 'taut init . --format json' again"
        )
    expectations = {
        name: feature_answers.get(name, "required" if evidence[name] else "absent")
        for name in BUILTIN_ASSURANCE_FEATURES
    }
    questions: list[InitQuestion] = []
    if not accepted:
        questions.append(
            InitQuestion(
                "architecture.accept_observed",
                "현재 import 관계에서 계산한 최소 allow 그래프를 초기 정책으로 사용할까요?",
                ("accept", "review"),
                "review",
                paths,
            )
        )
    for name in BUILTIN_ASSURANCE_FEATURES:
        if name not in feature_answers:
            questions.append(
                InitQuestion(
                    f"feature.{name}",
                    f"{name} 정책 영역의 기대 상태를 확인하세요.",
                    ("required", "absent"),
                    expectations[name],
                    tuple(evidence[name]),
                )
            )
    status = "ready" if not questions else "needs_input"
    return InitProposal(
        project_digest=digest,
        status=status,
        python_files=paths,
        detected_features=detected,
        questions=tuple(questions),
        toml=_render_configuration(root, paths, expectations),
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
        "schema_version": 4,
        "strict": {
            "type": "boolean",
            "default": True,
            "description": "Enforce findings and project assurance completeness.",
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


def _project_digest(root: Path, paths: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.encode())
        digest.update(b"\0")
        digest.update((root / path).read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _detect_features(root: Path, paths: tuple[str, ...]) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {name: [] for name in BUILTIN_ASSURANCE_FEATURES}
    for path in paths:
        content = (root / path).read_text(errors="replace")
        lowered_parts = {part.lower() for part in Path(path).parts}

        def mark(name: str, condition: bool, evidence_path: str = path) -> None:
            if condition:
                values[name].append(evidence_path)

        mark("api", "fastapi" in content or "APIRouter" in content)
        mark("schema", "pydantic" in content or "BaseModel" in content)
        mark(
            "dto",
            "@dataclass" in content
            and any(suffix in content for suffix in ("Data", "Result", "Row")),
        )
        mark("snapshot", "Snapshot" in content)
        mark("exception_registry", "Exception" in content or "ErrorCode" in content)
        mark("enum", "Enum" in content or "StrEnum" in content)
        mark("database", "sqlalchemy" in content)
        mark("transaction", "AsyncSession" in content or ".commit(" in content)
        mark(
            "external_calls",
            any(
                token in content for token in ("httpx", "requests", "openai", "anthropic", "boto3")
            ),
        )
        mark("security", "os.getenv" in content or "os.environ" in content)
        mark("tests", "tests" in lowered_parts or Path(path).name.startswith("test_"))
        mark("migrations", "migrations" in lowered_parts or "alembic" in lowered_parts)
        mark("scripts", "scripts" in lowered_parts)
    return values


def _render_configuration(
    root: Path,
    paths: tuple[str, ...],
    expectations: dict[str, str],
) -> str:
    roles = _roles_for_paths(paths)
    allow = _observed_allow_graph(root, paths, roles)
    lines = [
        "[tool.taut]",
        "schema_version = 4",
        'packs = ["taut.backend"]',
        'providers = ["taut.python-core", "taut.fastapi", "taut.pydantic", "taut.sqlalchemy"]',
        "strict = true",
        'include = ["*.py", "**/*.py"]',
        'source_roots = ["."]',
        "",
        "[tool.taut.roles]",
    ]
    for role, role_paths in sorted(roles.items()):
        lines.append(f"{role} = {_toml_array(role_paths)}")
    lines.extend(("", "[tool.taut.allow]"))
    for role, targets in sorted(allow.items()):
        lines.append(f"{role} = {_toml_array(tuple(sorted(targets)))}")
    zones = {
        "test": tuple(path for path in paths if "tests" in Path(path).parts),
        "migration": tuple(
            path for path in paths if {"migrations", "alembic"}.intersection(Path(path).parts)
        ),
        "script": tuple(path for path in paths if "scripts" in Path(path).parts),
    }
    nonempty_zones = {name: items for name, items in zones.items() if items}
    if nonempty_zones:
        lines.extend(("", "[tool.taut.zones]"))
        for name, items in nonempty_zones.items():
            lines.append(f"{name} = {_toml_array(items)}")
    lines.extend(("", "[tool.taut.assurance]", "max_approvals = 0", "max_inline_ignores = 0"))
    lines.extend(("", "[tool.taut.assurance.features]"))
    lines.extend(f'{name} = "{expectations[name]}"' for name in BUILTIN_ASSURANCE_FEATURES)
    return "\n".join(lines) + "\n"


def _roles_for_paths(paths: tuple[str, ...]) -> dict[str, tuple[str, ...]]:
    grouped: dict[str, list[str]] = {}
    for path in paths:
        parts = tuple(part.lower() for part in Path(path).parts)
        stem = Path(path).stem.lower()
        role = "application"
        candidates = (
            ("test", "tests" in parts or stem.startswith("test_")),
            ("migration", "migrations" in parts or "alembic" in parts),
            ("script", "scripts" in parts),
            ("router", "routers" in parts or stem in {"api", "router", "routes"}),
            ("dto", "dto" in stem),
            ("snapshot", "snapshot" in stem),
            ("exception", "exception" in stem or stem == "errors"),
            ("enum", "enum" in stem),
            ("schema", "schema" in stem),
            ("model", "model" in stem),
            ("adapter", any(token in stem for token in ("adapter", "external", "client", "store"))),
            ("service", "service" in stem or "services" in parts),
            ("configuration", stem in {"config", "settings"}),
            ("bootstrap", stem in {"main", "bootstrap", "container"}),
        )
        for candidate, matched in candidates:
            if matched:
                role = candidate
                break
        grouped.setdefault(role, []).append(path)
    return {name: tuple(sorted(items)) for name, items in grouped.items()}


def _observed_allow_graph(
    root: Path,
    paths: tuple[str, ...],
    roles: dict[str, tuple[str, ...]],
) -> dict[str, set[str]]:
    role_by_module: dict[str, str] = {}
    for role, role_paths in roles.items():
        for path in role_paths:
            module = path.removesuffix(".py").replace("/", ".")
            if module.endswith(".__init__"):
                module = module.removesuffix(".__init__")
            role_by_module[module] = role
    result = {role: {role} for role in roles}
    for path in paths:
        source_module = path.removesuffix(".py").replace("/", ".").removesuffix(".__init__")
        source_role = role_by_module.get(source_module)
        if source_role is None:
            continue
        try:
            tree = ast.parse((root / path).read_text())
        except (OSError, UnicodeError, SyntaxError):
            continue
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        for target_module, target_role in role_by_module.items():
            if any(
                name == target_module
                or name.startswith(f"{target_module}.")
                or target_module.startswith(f"{name}.")
                for name in imported
            ):
                result[source_role].add(target_role)
    return result


def _toml_array(values: tuple[str, ...]) -> str:
    return "[" + ", ".join(json.dumps(value) for value in values) + "]"
