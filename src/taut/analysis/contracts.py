from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from taut.domain.facts import ModuleFacts, SourceKind
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, SymbolId
from taut.domain.issues import EngineIssue
from taut.domain.location import ProjectPath
from taut.domain.relations import ModuleRelations


@dataclass(frozen=True, order=True)
class ProjectRoot:
    value: Path

    def __post_init__(self) -> None:
        if not self.value.is_absolute():
            raise ValueError("project root must be an absolute path")


@dataclass(frozen=True, order=True)
class LanguageSettings:
    language: str = "python"
    target_version: str = "3.12"


@dataclass(frozen=True, order=True)
class ContextManagerProvider:
    symbol: SymbolId
    item_type: SymbolId


@dataclass(frozen=True, order=True)
class ResolverSettings:
    source_roots: tuple[ProjectPath, ...] = (ProjectPath("."),)
    context_manager_providers: tuple[ContextManagerProvider, ...] = ()

    def __post_init__(self) -> None:
        symbols = tuple(provider.symbol for provider in self.context_manager_providers)
        if len(symbols) != len(set(symbols)):
            raise ValueError("context manager provider symbols must be unique")
        if self.context_manager_providers != tuple(sorted(self.context_manager_providers)):
            raise ValueError("context manager providers must be sorted")


@dataclass(frozen=True, order=True)
class SourceInput:
    path: ProjectPath
    module_id: ModuleId
    kind: SourceKind
    is_policy_target: bool
    is_package: bool
    content: str
    content_hash: str

    def __post_init__(self) -> None:
        if len(self.content_hash) != 64:
            raise ValueError("source content hash must be a sha256 digest")


@dataclass(frozen=True)
class AnalysisRequest:
    project_root: ProjectRoot
    sources: tuple[SourceInput, ...]
    language: LanguageSettings
    resolver: ResolverSettings
    adapter_versions: FrozenMap[str, str]

    def __post_init__(self) -> None:
        identities = tuple(source.module_id for source in self.sources)
        if len(identities) != len(set(identities)):
            raise ValueError("analysis request contains duplicate module ids")
        paths = tuple(source.path.value.casefold() for source in self.sources)
        if len(paths) != len(set(paths)):
            raise ValueError("analysis request contains duplicate or case-conflicting paths")
        if self.sources != tuple(sorted(self.sources, key=lambda source: source.path.value)):
            raise ValueError("analysis sources must be sorted by project path")


@dataclass(frozen=True, order=True)
class AdapterIdentity:
    name: str
    version: str


@dataclass(frozen=True)
class ModuleAnalysisResult:
    facts: ModuleFacts
    issues: tuple[EngineIssue, ...]
    relations: ModuleRelations = field(default_factory=ModuleRelations)


class LanguageAdapter(Protocol):
    identity: AdapterIdentity

    def analyze_module(
        self,
        source: SourceInput,
        resolver: ResolverSettings | None = None,
    ) -> ModuleAnalysisResult: ...

    def analyze_modules(
        self,
        sources: tuple[SourceInput, ...],
        resolver: ResolverSettings,
        workers: int,
    ) -> tuple[ModuleAnalysisResult, ...]: ...
