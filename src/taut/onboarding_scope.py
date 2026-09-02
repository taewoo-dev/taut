"""Evidence-based source-root discovery for machine-readable onboarding."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from taut.analysis.module_identity import module_identity, most_specific_source_root
from taut.domain.ids import ModuleId
from taut.loading.errors import PolicyConfigError


@dataclass(frozen=True, order=True)
class InitSourceRootEvidence:
    path: str
    kind: str
    source: str
    confidence: str

    def json_payload(self) -> dict[str, str]:
        return {
            "path": self.path,
            "kind": self.kind,
            "source": self.source,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class InitSourceScope:
    source_roots: tuple[str, ...]
    evidence: tuple[InitSourceRootEvidence, ...]
    conflicts: tuple[str, ...]
    requires_review: bool
    metadata_files: tuple[str, ...]

    def json_payload(self) -> dict[str, object]:
        return {
            "recommended_source_roots": self.source_roots,
            "requires_review": self.requires_review,
            "evidence": [item.json_payload() for item in self.evidence],
            "conflicts": self.conflicts,
        }

    def question_evidence(self) -> tuple[str, ...]:
        observed = tuple(
            f"{item.kind}:{item.source} -> {item.path} ({item.confidence})"
            for item in self.evidence
        )
        return observed + self.conflicts


def observe_source_scope(root: Path, python_paths: tuple[str, ...]) -> InitSourceScope:
    evidence: list[InitSourceRootEvidence] = []
    conflicts: list[str] = []
    project_directories, metadata_files = _project_directories(root, conflicts)
    for project_directory in project_directories:
        pyproject = project_directory / "pyproject.toml"
        if pyproject.is_file():
            document = _read_pyproject(root, pyproject, conflicts)
            if document is not None:
                _configured_roots(root, project_directory, pyproject, document, evidence, conflicts)
        conventional = project_directory / "src"
        if conventional.is_dir() and any(conventional.rglob("*.py")):
            _add_evidence(
                root,
                conventional,
                "src_layout",
                _relative(root, project_directory / "pyproject.toml"),
                "medium",
                evidence,
                conflicts,
            )

    roots = {item.path for item in evidence}
    if not roots or any(not _covered(path, roots) for path in python_paths):
        evidence.append(InitSourceRootEvidence(".", "coverage_fallback", "Python sources", "low"))
        roots.add(".")
    for source_root in roots:
        root_init = "__init__.py" if source_root == "." else f"{source_root}/__init__.py"
        if root_init in python_paths:
            conflicts.append(
                f"source root has a non-importable __init__.py; exclude it or choose another root: "
                f"{root_init}"
            )
    source_roots = tuple(sorted(roots, key=lambda value: (value != ".", value)))
    return InitSourceScope(
        source_roots=source_roots,
        evidence=tuple(sorted(set(evidence))),
        conflicts=tuple(sorted(set(conflicts))),
        requires_review=source_roots != (".",) or bool(conflicts),
        metadata_files=metadata_files,
    )


def selected_source_roots(
    root: Path,
    python_paths: tuple[str, ...],
    observed: InitSourceScope,
    answers: dict[str, object] | None,
) -> tuple[tuple[str, ...], bool]:
    if answers is None:
        return observed.source_roots, False
    accepted = answers.get("accept_observed_source_scope", False)
    if not isinstance(accepted, bool):
        raise PolicyConfigError("init answers.accept_observed_source_scope must be a boolean")
    raw_override = answers.get("source_roots")
    if accepted and raw_override is not None:
        raise PolicyConfigError(
            "init answers cannot combine accept_observed_source_scope with source_roots"
        )
    if raw_override is not None:
        return _validated_roots(root, python_paths, raw_override), True
    if accepted:
        if observed.conflicts:
            raise PolicyConfigError(
                "observed source scope has conflicts; provide explicit init answers.source_roots"
            )
        return observed.source_roots, True
    return observed.source_roots, not observed.requires_review


def module_name(path: str, source_roots: tuple[str, ...]) -> str:
    return module_details(path, source_roots)[0].value


def module_details(path: str, source_roots: tuple[str, ...]) -> tuple[ModuleId, bool]:
    source = PurePosixPath(path)
    roots = tuple(PurePosixPath(root) for root in source_roots)
    selected = most_specific_source_root(source, roots)
    if selected is None:
        raise ValueError(f"Python path is outside configured source roots: {path}")
    relative = source if selected == PurePosixPath(".") else source.relative_to(selected)
    return module_identity(Path(*relative.parts))


def _project_directories(
    root: Path, conflicts: list[str]
) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    directories = {root}
    metadata = set[str]()
    root_pyproject = root / "pyproject.toml"
    if not root_pyproject.is_file():
        return (root,), ()
    metadata.add("pyproject.toml")
    document = _read_pyproject(root, root_pyproject, conflicts)
    if document is None:
        return (root,), tuple(sorted(metadata))
    workspace = _mapping(_mapping(document.get("tool")).get("uv"))
    workspace = _mapping(workspace.get("workspace"))
    members = _string_sequence(workspace.get("members"))
    excludes = _string_sequence(workspace.get("exclude"))
    for pattern in members:
        matches = [
            path
            for path in root.glob(pattern)
            if path.is_dir()
            and path.resolve().is_relative_to(root)
            and not any(path.match(exclude) for exclude in excludes)
        ]
        if not matches:
            conflicts.append(f"uv workspace member pattern matched no directories: {pattern}")
        for member in matches:
            directories.add(member)
            member_pyproject = member / "pyproject.toml"
            if member_pyproject.is_file():
                metadata.add(_relative(root, member_pyproject))
            else:
                conflicts.append(
                    f"uv workspace member has no pyproject.toml: {_relative(root, member)}"
                )
    return tuple(sorted(directories)), tuple(sorted(metadata))


def _configured_roots(
    root: Path,
    project_directory: Path,
    pyproject: Path,
    document: dict[str, object],
    evidence: list[InitSourceRootEvidence],
    conflicts: list[str],
) -> None:
    source = _relative(root, pyproject)
    tool = _mapping(document.get("tool"))

    hatch = _mapping(_mapping(_mapping(tool.get("hatch")).get("build")).get("targets"))
    wheel = _mapping(hatch.get("wheel"))
    for package in _string_sequence(wheel.get("packages")):
        package_path = project_directory / package
        _add_evidence(
            root,
            package_path.parent,
            "hatch_wheel_packages",
            source,
            "high",
            evidence,
            conflicts,
            required_path=package_path,
        )

    setuptools = _mapping(tool.get("setuptools"))
    package_dir = setuptools.get("package-dir")
    if isinstance(package_dir, dict):
        package_mapping = cast(dict[object, object], package_dir)
        base = package_mapping.get("")
        if isinstance(base, str):
            _add_evidence(
                root,
                project_directory / base,
                "setuptools_package_dir",
                source,
                "high",
                evidence,
                conflicts,
            )
        if any(key != "" for key in package_mapping):
            message = "setuptools package-specific directory aliases require explicit source_roots"
            conflicts.append(f"{message}: {source}")

    poetry = _mapping(tool.get("poetry"))
    packages = poetry.get("packages")
    if isinstance(packages, list):
        for item in cast(list[object], packages):
            mapping = _mapping(item)
            include = mapping.get("include")
            origin = mapping.get("from", ".")
            if isinstance(include, str) and isinstance(origin, str):
                _add_evidence(
                    root,
                    project_directory / origin,
                    "poetry_packages",
                    source,
                    "high",
                    evidence,
                    conflicts,
                    required_path=project_directory / origin / include,
                )

    pdm = _mapping(_mapping(tool.get("pdm")).get("build"))
    pdm_package_dir = pdm.get("package-dir")
    if isinstance(pdm_package_dir, str):
        _add_evidence(
            root,
            project_directory / pdm_package_dir,
            "pdm_package_dir",
            source,
            "high",
            evidence,
            conflicts,
        )


def _add_evidence(
    root: Path,
    candidate: Path,
    kind: str,
    source: str,
    confidence: str,
    evidence: list[InitSourceRootEvidence],
    conflicts: list[str],
    *,
    required_path: Path | None = None,
) -> None:
    resolved = candidate.resolve()
    required = (required_path or candidate).resolve()
    if not resolved.is_relative_to(root) or not required.is_relative_to(root):
        conflicts.append(f"package metadata points outside the project: {candidate}")
        return
    if not candidate.is_dir() or not (required_path or candidate).exists():
        missing = _relative(root, required_path or candidate)
        conflicts.append(f"package metadata points to a missing path: {missing}")
        return
    evidence.append(InitSourceRootEvidence(_relative(root, candidate), kind, source, confidence))


def _validated_roots(root: Path, python_paths: tuple[str, ...], raw: object) -> tuple[str, ...]:
    if not isinstance(raw, list) or not raw:
        raise PolicyConfigError("init answers.source_roots must be a non-empty string array")
    values = cast(list[object], raw)
    normalized: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not value:
            raise PolicyConfigError("init answers.source_roots must be a non-empty string array")
        pure = PurePosixPath(value)
        if pure.is_absolute() or ".." in pure.parts:
            raise PolicyConfigError(f"invalid init source root: {value}")
        candidate = root if value == "." else root.joinpath(*pure.parts)
        if not candidate.is_dir() or not candidate.resolve().is_relative_to(root):
            raise PolicyConfigError(f"init source root does not exist inside project: {value}")
        normalized.add("." if value == "." else pure.as_posix().rstrip("/"))
    if any(not _covered(path, normalized) for path in python_paths):
        raise PolicyConfigError(
            "init answers.source_roots do not cover every discovered Python file"
        )
    return tuple(sorted(normalized, key=lambda value: (value != ".", value)))


def _covered(path: str, roots: set[str]) -> bool:
    source = PurePosixPath(path)
    return any(root == "." or source.is_relative_to(PurePosixPath(root)) for root in roots)


def _read_pyproject(root: Path, path: Path, conflicts: list[str]) -> dict[str, object] | None:
    try:
        value = tomllib.loads(path.read_text())
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        conflicts.append(f"cannot read {_relative(root, path)}: {error.__class__.__name__}")
        return None
    return cast(dict[str, object], value)


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    return {str(key): item for key, item in cast(dict[object, object], value).items()}


def _string_sequence(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in cast(list[object], value) if isinstance(item, str))


def _relative(root: Path, path: Path) -> str:
    value = path.relative_to(root).as_posix()
    return value or "."
