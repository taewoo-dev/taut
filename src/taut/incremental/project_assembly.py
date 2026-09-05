from __future__ import annotations

from dataclasses import dataclass, fields

from taut.analysis.contracts import AnalysisRequest, ModuleAnalysisResult
from taut.analysis.project_analyzer import ProjectAnalyzer, analysis_digest, resolution_coverage
from taut.analysis.project_index import build_project_index
from taut.domain.facts import CompletenessState, ModuleFacts
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, SnapshotId
from taut.domain.relations import ProjectRelations
from taut.domain.snapshot import (
    AnalysisCoverage,
    AnalysisInputDigest,
    AnalysisSnapshot,
    ResolutionCoverage,
)


def _index_input(module: ModuleFacts) -> tuple[object, ...]:
    # Exactly the facts consumed by project_index, including occurrence locations.
    return (
        module.module.id,
        tuple(
            tuple(getattr(item, field.name) for field in fields(item) if field.name != "provenance")
            for item in module.imports
        ),
        tuple(
            (item.symbol_id, item.enclosing_symbol, item.location, item.id)
            for item in module.definitions
        ),
        tuple(
            (item.symbol_id, item.owner_symbol, item.name, item.location, item.id)
            for item in module.fields
        ),
        tuple(
            (item.symbol_id, item.lexical_owner, item.local_name, item.location, item.id)
            for item in module.bindings
        ),
    )


@dataclass(frozen=True)
class ModuleContribution:
    result: ModuleAnalysisResult
    index_input: tuple[object, ...]
    relations: ProjectRelations
    calls: ResolutionCoverage
    references: ResolutionCoverage

    @classmethod
    def build(cls, result: ModuleAnalysisResult) -> ModuleContribution:
        facts = result.facts
        relations = result.relations
        return cls(
            result,
            _index_input(facts),
            ProjectRelations(relations.bindings, (), relations.use_edges),
            resolution_coverage(tuple(call.ref.state for call in facts.calls)),
            resolution_coverage(tuple(ref.ref.state for ref in facts.references)),
        )


@dataclass(frozen=True)
class ProjectAssemblyState:
    snapshot: AnalysisSnapshot
    contributions: FrozenMap[ModuleId, ModuleContribution]
    recomputed_modules: int
    reused_project_index: bool
    schema_version: int = 1

    @classmethod
    def build(
        cls,
        request: AnalysisRequest,
        results: tuple[ModuleAnalysisResult, ...],
        prior: ProjectAssemblyState | None = None,
    ) -> ProjectAssemblyState:
        if prior is not None and prior.schema_version != 1:
            prior = None
        if tuple(source.module_id for source in request.sources) != tuple(
            result.facts.module.id for result in results
        ):
            # Keep the fresh oracle's detailed input-contract errors.
            ProjectAnalyzer.assemble(request, results)
            raise ValueError("analysis input mismatch")
        contributions: dict[ModuleId, ModuleContribution] = {}
        recomputed = 0
        for result in results:
            module_id = result.facts.module.id
            old = prior.contributions.get(module_id) if prior is not None else None
            if old is not None and old.result is result:
                contributions[module_id] = old
            else:
                contributions[module_id] = ModuleContribution.build(result)
                recomputed += 1
        reuse_index = (
            prior is not None
            and contributions.keys() == prior.contributions.keys()
            and all(
                part.index_input == prior.contributions[module_id].index_input
                for module_id, part in contributions.items()
            )
        )
        modules = FrozenMap((result.facts.module.id, result.facts) for result in results)
        project = (
            prior.snapshot.project
            if prior is not None and reuse_index
            else build_project_index(modules.values())
        )
        relations = ProjectRelations.from_validated_parts(
            tuple(part.relations for part in contributions.values()), project.import_edges
        )
        states = tuple(module.completeness.state for module in modules.values())

        def total(attribute: str) -> ResolutionCoverage:
            values = tuple(getattr(part, attribute).values() for part in contributions.values())
            return (
                ResolutionCoverage(*(sum(items) for items in zip(*values, strict=True)))
                if values
                else ResolutionCoverage()
            )

        coverage = AnalysisCoverage(
            len(results),
            states.count(CompletenessState.COMPLETE),
            states.count(CompletenessState.PARTIAL),
            states.count(CompletenessState.FAILED),
            calls=total("calls"),
            references=total("references"),
            resolved_imports=len(project.import_edges),
            unresolved_imports=len(project.unresolved_imports),
        )
        digest = analysis_digest(request)
        snapshot = AnalysisSnapshot(
            SnapshotId(digest),
            AnalysisInputDigest(digest),
            modules,
            project,
            relations,
            FrozenMap(),
            coverage,
            tuple(issue for result in results for issue in result.issues),
        )
        return cls(snapshot, FrozenMap(contributions), recomputed, reuse_index)
