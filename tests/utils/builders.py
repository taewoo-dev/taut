from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

from taut.analysis.contracts import (
    AnalysisRequest,
    LanguageSettings,
    ProjectRoot,
    ResolverSettings,
    SourceInput,
)
from taut.analysis.framework.fastapi import (
    FastAPIDependencyFact,
    FastAPIEndpointFact,
    FastAPIResponseModelFact,
    FastAPIRouterFact,
)
from taut.analysis.framework.pydantic_facts import (
    PydanticConfigFact,
    PydanticFieldFact,
    PydanticModelFact,
    PydanticOperationFact,
    PydanticSerializerFact,
    PydanticValidatorFact,
)
from taut.analysis.framework.sqlalchemy_facts import SQLAlchemyRawSQLFact
from taut.analysis.project_analyzer import ProjectAnalyzer
from taut.analysis.providers import apply_fact_providers
from taut.analysis.python.language_adapter import PythonAstAdapter
from taut.analysis.semantic_model import SnapshotSemanticModel
from taut.configuration.catalog import CatalogEntry, EffectCatalog, EffectResolver
from taut.configuration.effective_policy import (
    BoundaryPolicy,
    CodeConventionPolicy,
    EffectivePolicy,
    ImportBoundary,
    PolicyApproval,
    SecurityPolicy,
)
from taut.configuration.manifest import (
    ProjectManifest,
    Role,
    RoleMatcher,
    Zone,
    ZoneMatcher,
)
from taut.domain.analysis_state import AnalysisStage, CompletenessState
from taut.domain.evaluations import RuleLevel, RuleSetting
from taut.domain.facts import CallFact, ResolutionState, SourceKind
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, RuleId, SymbolId
from taut.domain.location import ConfigLocation, ProjectPath
from taut.domain.snapshot import AnalysisSnapshot
from taut.loading.config_loader import default_project_configuration
from taut.policy.context import PolicyContext
from taut.policy.packs import builtin_backend_providers

RULE_IDS = tuple(
    RuleId(value)
    for value in (
        "TIME001",
        "ARCH000",
        "TX001",
        "TX003",
        "SESSION001",
        "SESSION002",
        "SESSION003",
        "IMPORT001",
        "SIZE001",
        "BOUNDARY001",
        "BOUNDARY002",
        "BOUNDARY003",
        "ADAPTER001",
        "ENTRY001",
        "SERVICE001",
        "QUERY001",
        "MODEL001",
        "WIRING001",
        "ADAPTER002",
        "DEPENDS001",
        "CONFIG001",
        "TEST001",
        "TEST002",
        "HTTP001",
        "LOG001",
        "ARCH001",
        "ARCH002",
        "IMPORT002",
        "RUNTIME001",
        "TX002",
        "DTO001",
        "DTO002",
        "SNAPSHOT001",
        "SCHEMA001",
        "SCHEMA002",
        "SCHEMA003",
        "API001",
        "API002",
        "API003",
        "ENUM001",
        "ORM001",
        "ORM002",
        "DB001",
        "SQL001",
        "EXC001",
        "ASYNC001",
        "SEC001",
        "CAT001",
        "IGNORE001",
    )
)


def _provider_fact_state(fact: object, state: ResolutionState) -> object:
    if isinstance(
        fact,
        (
            FastAPIDependencyFact,
            FastAPIEndpointFact,
            FastAPIResponseModelFact,
            FastAPIRouterFact,
            PydanticConfigFact,
            PydanticFieldFact,
            PydanticModelFact,
            PydanticOperationFact,
            PydanticSerializerFact,
            PydanticValidatorFact,
            SQLAlchemyRawSQLFact,
        ),
    ):
        return replace(fact, confidence=state)
    return fact


def _call_fact_state(
    fact: CallFact,
    state: ResolutionState,
    relevant: tuple[SymbolId, ...],
) -> CallFact:
    if state is ResolutionState.RESOLVED:
        return fact
    candidates: tuple[SymbolId, ...]
    if state is ResolutionState.AMBIGUOUS:
        candidates = (relevant or (SymbolId("candidate.one"),)) + (SymbolId("candidate.two"),)
    elif state is ResolutionState.CONDITIONAL:
        candidates = relevant or (SymbolId("candidate.one"),)
    else:
        candidates = ()
    return replace(
        fact,
        ref=replace(fact.ref, state=state, symbol=None, candidates=candidates),
    )


def make_source(
    path: str,
    content: str,
    *,
    module_id: str | None = None,
    is_policy_target: bool = True,
) -> SourceInput:
    project_path = ProjectPath(path)
    is_package = path.endswith("/__init__.py")
    if module_id is None:
        logical = path.removesuffix("/__init__.py") if is_package else path.removesuffix(".py")
        module_id = logical.replace("/", ".")
    return SourceInput(
        path=project_path,
        module_id=ModuleId(module_id),
        kind=SourceKind.FIRST_PARTY,
        is_policy_target=is_policy_target,
        is_package=is_package,
        content=content,
        content_hash=hashlib.sha256(content.encode()).hexdigest(),
    )


def analyze(
    *sources: SourceInput,
    resolver: ResolverSettings | None = None,
    workers: int = 1,
) -> AnalysisSnapshot:
    adapter = PythonAstAdapter()
    resolver_settings = resolver or ResolverSettings()
    request = AnalysisRequest(
        project_root=ProjectRoot(Path("/project")),
        sources=tuple(sorted(sources, key=lambda source: source.path.value)),
        language=LanguageSettings(),
        resolver=resolver_settings,
        adapter_versions=FrozenMap(((adapter.identity.name, adapter.identity.version),)),
    )
    return ProjectAnalyzer(adapter).analyze(request, workers=workers)


def make_context(
    snapshot: AnalysisSnapshot,
    *,
    roles: dict[str, tuple[str, ...]],
    zones: dict[str, tuple[str, ...]] | None = None,
    levels: dict[str, RuleLevel] | None = None,
    allowed_imports: dict[str, frozenset[str]] | None = None,
    transaction_owners: frozenset[str] = frozenset(),
    transaction_participants: frozenset[str] = frozenset(),
    transaction_session_providers: frozenset[str] = frozenset(),
    rule_zones: dict[str, frozenset[str]] | None = None,
    approvals: tuple[PolicyApproval, ...] = (),
    import_boundaries: tuple[
        tuple[str, frozenset[str], tuple[str, ...]]
        | tuple[str, frozenset[str], tuple[str, ...], tuple[str, ...]],
        ...,
    ] = (),
    default_max_lines: int = 700,
    max_lines_by_role: dict[str, int] | None = None,
    boundary_policy: BoundaryPolicy | None = None,
    code_policy: CodeConventionPolicy | None = None,
    security_policy: SecurityPolicy | None = None,
    extra_catalog_entries: tuple[CatalogEntry, ...] = (),
    provider_state: ResolutionState | None = None,
    missing_capability: str | None = None,
    incomplete_modules: frozenset[str] = frozenset(),
    fact_state: ResolutionState | None = None,
    fact_candidates: tuple[SymbolId, ...] = (),
) -> PolicyContext:
    snapshot = apply_fact_providers(snapshot, builtin_backend_providers())
    if fact_state is not None:
        snapshot = replace(
            snapshot,
            modules=FrozenMap(
                (
                    module_id,
                    replace(
                        module,
                        calls=tuple(
                            _call_fact_state(call, fact_state, fact_candidates)
                            for call in module.calls
                        ),
                    ),
                )
                for module_id, module in snapshot.modules.items()
            ),
            capabilities=FrozenMap(
                (
                    capability,
                    tuple(_provider_fact_state(fact, fact_state) for fact in facts),
                )
                for capability, facts in snapshot.capabilities.items()
            ),
        )
    if incomplete_modules:
        modules = FrozenMap(
            (
                module_id,
                replace(
                    module,
                    completeness=replace(
                        module.completeness,
                        state=CompletenessState.PARTIAL,
                        stage=AnalysisStage.PARSED,
                    ),
                )
                if module_id.value in incomplete_modules
                else module,
            )
            for module_id, module in snapshot.modules.items()
        )
        incomplete_count = sum(
            module_id.value in incomplete_modules for module_id in snapshot.modules
        )
        snapshot = replace(
            snapshot,
            modules=modules,
            coverage=replace(
                snapshot.coverage,
                complete_modules=snapshot.coverage.complete_modules - incomplete_count,
                partial_modules=snapshot.coverage.partial_modules + incomplete_count,
            ),
        )
    if provider_state is not None:
        snapshot = replace(
            snapshot,
            capabilities=FrozenMap(
                (
                    capability,
                    tuple(_provider_fact_state(fact, provider_state) for fact in facts),
                )
                for capability, facts in snapshot.capabilities.items()
            ),
        )
    if missing_capability is not None:
        snapshot = replace(
            snapshot,
            capabilities=FrozenMap(
                (name, values)
                for name, values in snapshot.capabilities.items()
                if name != missing_capability
            ),
            capability_provenance=FrozenMap(
                (name, provenance)
                for name, provenance in snapshot.capability_provenance.items()
                if name != missing_capability
            ),
        )
    location = ConfigLocation(ProjectPath("policy.toml"))
    matchers = tuple(
        RoleMatcher(Role(role), patterns, location) for role, patterns in roles.items()
    )
    zone_matchers = tuple(
        ZoneMatcher(Zone(zone), patterns, location) for zone, patterns in (zones or {}).items()
    )
    manifest = ProjectManifest(matchers, zone_matchers, Zone("prod"), location)
    classifications = manifest.classify(snapshot)
    selected_levels = levels or {rule_id.value: RuleLevel.ENFORCED for rule_id in RULE_IDS}
    settings = FrozenMap(
        (
            rule_id,
            RuleSetting(selected_levels.get(rule_id.value, RuleLevel.OFF), FrozenMap()),
        )
        for rule_id in RULE_IDS
    )
    allowed = FrozenMap(
        (Role(source), frozenset(Role(target) for target in targets))
        for source, targets in (allowed_imports or {}).items()
    )
    policy = EffectivePolicy(
        rules=settings,
        allowed_imports=allowed,
        transaction_owner_roles=frozenset(Role(role) for role in transaction_owners),
        transaction_participant_roles=frozenset(Role(role) for role in transaction_participants),
        transaction_session_providers=frozenset(
            SymbolId(symbol) for symbol in transaction_session_providers
        ),
        rule_zones=FrozenMap(
            (RuleId(rule), frozenset(Zone(zone) for zone in zones))
            for rule, zones in (rule_zones or {}).items()
        ),
        approvals=tuple(sorted(approvals, key=lambda approval: approval.key)),
        import_boundaries=tuple(
            ImportBoundary(
                item[0],
                frozenset(Role(role) for role in item[1]),
                tuple(sorted(ModuleId(module) for module in item[2])),
                tuple(sorted(item[3])) if len(item) == 4 else (),
            )
            for item in import_boundaries
        ),
        default_max_lines=default_max_lines,
        max_lines_by_role=FrozenMap(
            (Role(role), maximum) for role, maximum in (max_lines_by_role or {}).items()
        ),
        boundaries=boundary_policy or BoundaryPolicy(),
        code=code_policy or CodeConventionPolicy(),
        security=security_policy or SecurityPolicy(),
    )
    base_catalog = default_project_configuration().catalog.entries
    catalog_values = dict(base_catalog.items())
    catalog_values.update((entry.symbol, entry) for entry in extra_catalog_entries)
    return PolicyContext(
        model=SnapshotSemanticModel(snapshot),
        classification=classifications,
        effects=EffectResolver(),
        catalog=EffectCatalog(FrozenMap(catalog_values)),
        policy=policy,
    )
