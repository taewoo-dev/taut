from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

from taut.analysis.contracts import SourceInput
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
    seen_paths: set[str] = set()
    seen_modules: set[ModuleId] = set()
    project_root = project_root.resolve()
    resolved_project_root = project_root
    candidates = _included_python_paths(project_root, config.include)

    for source_root in config.source_roots:
        absolute_root = (project_root / source_root.value).resolve()
        if not absolute_root.is_relative_to(resolved_project_root):
            issues.append(_discovery_issue("SOURCE_ROOT_OUTSIDE", source_root.value))
            continue
        if not absolute_root.is_dir():
            issues.append(_discovery_issue("SOURCE_ROOT_MISSING", source_root.value))
            continue
        for absolute_path in candidates:
            if not absolute_path.is_relative_to(absolute_root):
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
            if _matches(project_path.value, config.exclude):
                entries.append(DiscoveryEntry(project_path, False, "exclude 패턴과 일치"))
                continue
            folded = project_path.value.casefold()
            if folded in seen_paths:
                issues.append(_discovery_issue("SOURCE_PATH_CONFLICT", project_path.value))
                continue
            try:
                relative_source = absolute_path.relative_to(absolute_root)
                module_id, is_package = _module_identity(relative_source)
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
            if module_id in seen_modules:
                issues.append(_discovery_issue("SOURCE_MODULE_CONFLICT", module_id.value))
                continue
            seen_paths.add(folded)
            seen_modules.add(module_id)
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
    return SourceDiscoveryResult(
        sources=tuple(sorted(sources, key=lambda source: source.path.value)),
        report=SourceDiscoveryReport(tuple(sorted(entries, key=lambda entry: entry.path.value))),
        issues=tuple(sorted(issues, key=lambda issue: (issue.code, issue.message))),
    )


def _matches(path: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatchcase(path, pattern) for pattern in patterns)


def _included_python_paths(project_root: Path, patterns: tuple[str, ...]) -> tuple[Path, ...]:
    candidates = {
        path
        for pattern in patterns
        for path in project_root.glob(pattern)
        if path.name.endswith(".py") and path.is_file()
    }
    return tuple(sorted(candidates))


def _module_identity(relative_path: Path) -> tuple[ModuleId, bool]:
    parts = list(relative_path.parts)
    is_package = parts[-1] == "__init__.py"
    if is_package:
        parts = parts[:-1]
    else:
        parts[-1] = relative_path.stem
    if not parts:
        raise ValueError("source root __init__.py has no logical module name")
    return ModuleId(".".join(_module_part(part) for part in parts)), is_package


def _module_part(value: str) -> str:
    if value.isidentifier():
        return value
    readable = re.sub(r"\W", "_", value)
    if not readable or not readable.isidentifier():
        readable = "source"
    digest = hashlib.sha256(value.encode()).hexdigest()[:8]
    return f"{readable}_{digest}"


def _discovery_issue(code: str, subject: str, cause: str | None = None) -> EngineIssue:
    return EngineIssue(
        code=code,
        kind=EngineIssueKind.SOURCE_DISCOVERY_FAILURE,
        message=f"소스 파일을 검사 대상에 포함하지 못했습니다: {subject}",
        location=None,
        cause=cause,
    )
