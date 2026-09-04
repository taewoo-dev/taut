from __future__ import annotations

import hashlib
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

from taut.analysis.contracts import SourceInput
from taut.analysis.module_identity import module_identity, most_specific_source_root
from taut.configuration.model import ProjectConfiguration
from taut.domain.facts import SourceKind
from taut.domain.ids import ModuleId
from taut.domain.issues import EngineIssue, EngineIssueKind
from taut.domain.location import ProjectPath


@dataclass(frozen=True, order=True)
class DiscoveryEntry:
    path: ProjectPath
    included: bool
    reason: str


@dataclass(frozen=True)
class SourceDiscoveryReport:
    entries: tuple[DiscoveryEntry, ...]


@dataclass(frozen=True)
class SourceDiscoveryResult:
    sources: tuple[SourceInput, ...]
    report: SourceDiscoveryReport
    issues: tuple[EngineIssue, ...]


def discover_sources(
    project_root: Path,
    config: ProjectConfiguration,
) -> SourceDiscoveryResult:
    sources: list[SourceInput] = []
    entries: list[DiscoveryEntry] = []
    issues: list[EngineIssue] = []
    seen_paths: dict[str, ProjectPath] = {}
    seen_modules: dict[ModuleId, tuple[ProjectPath, str]] = {}
    project_root = project_root.resolve()
    resolved_project_root = project_root
    candidates, shadowed_stubs = _included_python_paths(
        project_root, (*config.include, *config.force_include)
    )

    valid_roots: list[tuple[ProjectPath, Path]] = []
    for source_root in config.source_roots:
        absolute_root = (project_root / source_root.value).resolve()
        if not absolute_root.is_relative_to(resolved_project_root):
            issues.append(_discovery_issue("SOURCE_ROOT_OUTSIDE", source_root.value))
            continue
        if not absolute_root.is_dir():
            issues.append(_discovery_issue("SOURCE_ROOT_MISSING", source_root.value))
            continue
        valid_roots.append((source_root, absolute_root))

    for absolute_path in candidates:
        matching_roots = [
            (source_root, absolute_root)
            for source_root, absolute_root in valid_roots
            if absolute_path.is_relative_to(absolute_root)
        ]
        if not matching_roots:
            continue
        selected_root = most_specific_source_root(
            absolute_path, tuple(item[1] for item in matching_roots)
        )
        if selected_root is None:
            continue
        try:
            project_path = ProjectPath(absolute_path.relative_to(project_root).as_posix())
        except ValueError:
            issues.append(_discovery_issue("SOURCE_PATH_INVALID", str(absolute_path)))
            continue
        if absolute_path.is_symlink() and not absolute_path.resolve().is_relative_to(
            project_root.resolve()
        ):
            issues.append(_discovery_issue("SOURCE_SYMLINK_OUTSIDE", project_path.value))
            entries.append(DiscoveryEntry(project_path, False, "프로젝트 밖 symlink"))
            continue
        if _matches(project_path.value, config.exclude) and not _matches(
            project_path.value, config.force_include
        ):
            entries.append(DiscoveryEntry(project_path, False, "exclude 패턴과 일치"))
            continue
        folded = project_path.value.casefold()
        previous_path = seen_paths.get(folded)
        if previous_path is not None:
            subject = f"{previous_path.value} and {project_path.value}"
            issues.append(_discovery_issue("SOURCE_PATH_CONFLICT", subject))
            continue
        try:
            relative_source = absolute_path.relative_to(selected_root)
            module_id, is_package = module_identity(relative_source)
            content = absolute_path.read_text()
        except (OSError, UnicodeError, ValueError) as error:
            issues.append(
                _discovery_issue(
                    "SOURCE_READ_FAILURE",
                    project_path.value,
                    error.__class__.__name__,
                )
            )
            continue
        selected_label = next(
            source_root.value
            for source_root, absolute_root in matching_roots
            if absolute_root == selected_root
        )
        previous_module = seen_modules.get(module_id)
        if previous_module is not None:
            previous_path, previous_root = previous_module
            subject = (
                f"module {module_id.value}: {previous_path.value} (root {previous_root}) and "
                f"{project_path.value} (root {selected_label})"
            )
            issues.append(_discovery_issue("SOURCE_MODULE_CONFLICT", subject))
            continue
        seen_paths[folded] = project_path
        seen_modules[module_id] = (project_path, selected_label)
        sources.append(
            SourceInput(
                path=project_path,
                module_id=module_id,
                kind=SourceKind.FIRST_PARTY,
                is_policy_target=True,
                is_package=is_package,
                content=content,
                content_hash=hashlib.sha256(content.encode()).hexdigest(),
            )
        )
        entries.append(DiscoveryEntry(project_path, True, "검사 대상"))
    if not sources:
        issues.append(_discovery_issue("NO_SOURCES", "일치하는 Python 파일이 없음"))
    entries.extend(
        DiscoveryEntry(
            ProjectPath(path.relative_to(project_root).as_posix()), False, "shadowed_stub"
        )
        for path in shadowed_stubs
    )
    return SourceDiscoveryResult(
        sources=tuple(sorted(sources, key=lambda source: source.path.value)),
        report=SourceDiscoveryReport(tuple(sorted(entries, key=lambda entry: entry.path.value))),
        issues=tuple(sorted(issues, key=lambda issue: (issue.code, issue.message))),
    )


def _matches(path: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatchcase(path, pattern) for pattern in patterns)


def _included_python_paths(
    project_root: Path, patterns: tuple[str, ...]
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    candidates = {
        path
        for pattern in patterns
        for path in project_root.glob(pattern)
        if path.name.endswith((".py", ".pyi")) and path.is_file()
    }
    implementations = {path.with_suffix("") for path in candidates if path.suffix == ".py"}
    shadowed = tuple(
        sorted(
            path
            for path in candidates
            if path.suffix == ".pyi" and path.with_suffix("") in implementations
        )
    )
    return tuple(sorted(candidates.difference(shadowed))), shadowed


def _discovery_issue(code: str, subject: str, cause: str | None = None) -> EngineIssue:
    return EngineIssue(
        code=code,
        kind=EngineIssueKind.SOURCE_DISCOVERY_FAILURE,
        message=f"소스 파일을 검사 대상에 포함하지 못했습니다: {subject}",
        location=None,
        cause=cause,
    )
