"""Canonical check pipeline shared by the CLI and the local daemon."""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field, replace
from pathlib import Path

from taut import __version__
from taut.analysis.contracts import (
    AdapterIdentity,
    AnalysisRequest,
    ContextManagerProvider,
    LanguageSettings,
    ModuleAnalysisResult,
    ProjectRoot,
    ResolverSettings,
    SourceInput,
)
from taut.analysis.providers import (
    FactProviderV1,
    apply_fact_providers,
    apply_fact_providers_incremental,
)
from taut.analysis.python.language_adapter import PythonAstAdapter
from taut.analysis.semantic_model import SnapshotSemanticModel
from taut.assurance import audit_project_assurance
from taut.cache import CacheKey, CacheStore
from taut.cache.authenticated import ModuleBundle, cache_signing_context
from taut.check_runtime import CheckRuntime, prepare_check_runtime
from taut.configuration.catalog import EffectResolver
from taut.configuration.model import ProjectConfiguration
from taut.configuration.validation import validate_classification_for_policy
from taut.domain.findings import Finding
from taut.domain.frozen import FrozenMap
from taut.domain.ids import SymbolId
from taut.domain.issues import EngineIssue
from taut.domain.location import ConfigPath
from taut.domain.reports import CoverageReport, RunReport
from taut.domain.snapshot import AnalysisSnapshot
from taut.finding_processing.finding_processor import FindingProcessor
from taut.finding_processing.report_builder import build_run_report
from taut.incremental import IncrementalProjectAnalyzer
from taut.loading.inline_ignores import load_inline_ignores
from taut.loading.source_discovery import discover_sources
from taut.policy.context import PolicyContext
from taut.policy.decision_digest import build_decision_digest
from taut.policy.engine import IncrementalPolicyResult, PolicyEngine
from taut.policy.packs import RulePackV1
from taut.policy.registry import RuleRegistry
from taut.reporting.json import render_json
from taut.reporting.text import render_text

_ASYNC_SESSION_TYPE = SymbolId("sqlalchemy.ext.asyncio.AsyncSession")
_TORTOISE_CONNECTION_TYPE = SymbolId("tortoise.backends.base.client.TransactionalDBClient")
_MINIMUM_PARALLEL_SOURCES = 100
_MAXIMUM_ANALYSIS_WORKERS = 4


@dataclass(frozen=True)
class CheckRequest:
    project_root: Path
    config_path: ConfigPath | None = None
    output_format: str = "text"
    show_inactive: bool = False
    verbose: bool = False
    use_color: bool = False
    width: int = 100


@dataclass(frozen=True)
class StageTiming:
    name: str
    milliseconds: float


@dataclass(frozen=True)
class CheckCounters:
    reparsed_modules: int = 0
    reused_modules: int = 0
    recomputed_providers: int = 0
    reused_providers: int = 0
    recomputed_evaluations: int = 0
    reused_evaluations: int = 0
    full_policy_rerun: bool = False


@dataclass(frozen=True)
class CheckResult:
    stdout: bytes
    stderr: bytes
    exit_code: int
    report: RunReport | None
    findings: tuple[Finding, ...] = ()
    coverage: CoverageReport | None = None
    issues: tuple[EngineIssue, ...] = ()
    timings: tuple[StageTiming, ...] = ()
    counters: CheckCounters = field(default_factory=CheckCounters)


class ResidentCheckSession:
    """Incremental state for exactly one canonical project root."""

    def __init__(self, project_root: Path, module_store: CacheStore | None = None) -> None:
        self.project_root = project_root.resolve()
        self._module_store = module_store
        self._closed = False
        self._identity: tuple[object, ...] | None = None
        self._config: ProjectConfiguration | None = None
        self._adapter = PythonAstAdapter()
        self._analyzer = IncrementalProjectAnalyzer(self._adapter)
        self._providers: tuple[FactProviderV1, ...] = ()
        self._packs: tuple[RulePackV1, ...] = ()
        self._registry: RuleRegistry | None = None
        self._engine: PolicyEngine | None = None
        self._prior_provider_snapshot: AnalysisSnapshot | None = None
        self._prior_policy_context: PolicyContext | None = None
        self._prior_policy_result: IncrementalPolicyResult | None = None

    def check(self, request: CheckRequest, runtime: CheckRuntime | None = None) -> CheckResult:
        if self._closed:
            raise RuntimeError("resident check session is closed")
        root = request.project_root.resolve()
        if root != self.project_root:
            raise ValueError("request project root differs from session root")
        prepared = runtime or prepare_check_runtime(root, request.config_path)
        if prepared.project_root != root or prepared.requested_config_path != request.config_path:
            raise ValueError("prepared runtime differs from request")
        identity = (root, *prepared.identity)
        if identity != self._identity:
            self._configure(prepared, identity)
        return self._run(request, prepared.config)

    def reset(self) -> None:
        self._identity = None
        self._config = None
        self._adapter = PythonAstAdapter()
        self._analyzer = IncrementalProjectAnalyzer(self._adapter)
        self._providers = ()
        self._packs = ()
        self._registry = None
        self._engine = None
        self._prior_provider_snapshot = None
        self._prior_policy_context = None
        self._prior_policy_result = None

    def close(self) -> None:
        self.reset()
        self._closed = True

    def __enter__(self) -> ResidentCheckSession:
        if self._closed:
            raise RuntimeError("resident check session is closed")
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _configure(self, runtime: CheckRuntime, identity: tuple[object, ...]) -> None:
        self.reset()
        self._config = runtime.config
        self._identity = identity
        self._adapter = runtime.adapter
        self._analyzer = IncrementalProjectAnalyzer(self._adapter)
        self._providers = runtime.providers
        self._packs = runtime.packs
        self._registry = runtime.registry
        self._engine = PolicyEngine(self._registry)

    def _run(self, request: CheckRequest, config: ProjectConfiguration) -> CheckResult:
        timings: list[StageTiming] = []
        started = time.perf_counter()
        discovery = discover_sources(self.project_root, config)
        _timed(timings, "discovery", started)

        context_managers = {
            ContextManagerProvider(
                symbol,
                config.policy.transaction_provider_item_types.get(
                    symbol, _context_manager_item_type(symbol)
                ),
            )
            for symbol in config.policy.transaction_session_providers
        }
        context_managers.update(
            ContextManagerProvider(symbol, symbol)
            for symbol in config.policy.boundaries.http_timeout_calls
        )
        analysis_request = AnalysisRequest(
            project_root=ProjectRoot(self.project_root),
            sources=discovery.sources,
            language=LanguageSettings(),
            resolver=ResolverSettings(
                source_roots=config.source_roots,
                context_manager_providers=tuple(sorted(context_managers)),
            ),
            adapter_versions=FrozenMap(
                ((self._adapter.identity.name, self._adapter.identity.version),)
            ),
        )
        module_cache = None
        if self._module_store is not None:
            resolver_identity = hashlib.sha256(
                repr(
                    (
                        __version__,
                        analysis_request.language,
                        analysis_request.resolver,
                        tuple(analysis_request.adapter_versions.items()),
                    )
                ).encode()
            ).hexdigest()
            module_cache = _DiskModuleCache(
                self._module_store,
                self._adapter.identity,
                resolver_identity,
                self.project_root,
            )
        started = time.perf_counter()
        snapshot = self._analyzer.analyze(
            analysis_request,
            workers=_analysis_workers(len(analysis_request.sources)),
            module_cache=module_cache,
        )
        _timed(timings, "analysis", started)
        changes = self._analyzer.last_changes
        impact = self._analyzer.last_impact

        started = time.perf_counter()
        prior_snapshot = self._prior_provider_snapshot
        if prior_snapshot is not None and not changes.touched and prior_snapshot.id == snapshot.id:
            snapshot = prior_snapshot
            recomputed_providers = 0
            reused_providers = len(self._providers)
        elif prior_snapshot is None:
            snapshot = apply_fact_providers(snapshot, self._providers)
            recomputed_providers = len(self._providers)
            reused_providers = 0
        else:
            snapshot = apply_fact_providers_incremental(
                snapshot, self._providers, prior_snapshot, impact.impacted
            )
            recomputed_providers = len(self._providers)
            reused_providers = 0
        _timed(timings, "providers", started)

        started = time.perf_counter()
        classifications = config.manifest.classify(snapshot)
        validate_classification_for_policy(classifications, config.policy)
        context = PolicyContext(
            model=SnapshotSemanticModel(snapshot),
            classification=classifications,
            effects=EffectResolver(),
            catalog=config.catalog,
            policy=config.policy,
        )
        if self._engine is None or self._registry is None:
            raise RuntimeError("resident check session is not configured")
        if self._prior_policy_context is None or self._prior_policy_result is None:
            policy_result = self._engine.run_tracked(context)
        else:
            policy_result = self._engine.run_incremental(
                context,
                self._prior_policy_context,
                self._prior_policy_result,
                changes,
                impact,
            )
        _timed(timings, "policy", started)

        started = time.perf_counter()
        ignore_result = load_inline_ignores(
            discovery.sources, frozenset(self._registry.definitions)
        )
        help_by_rule = FrozenMap(
            (rule_id, definition.help) for rule_id, definition in self._registry.definitions.items()
        )
        processing = FindingProcessor().process(
            findings=policy_result.result.findings,
            policy=config.policy,
            help_by_rule=help_by_rule,
            ignores=ignore_result.directives,
            classifications=classifications,
            canonicalize=context.model.canonical_symbol,
            preused_approval_keys=policy_result.result.approval_keys,
        )
        assurance = audit_project_assurance(
            self.project_root,
            config,
            discovery,
            snapshot,
            classifications,
            used_approvals=len(processing.approval_audit.used),
            used_ignores=len(processing.ignore_audit.used),
        )
        extension_assurance = tuple(
            issue
            for pack in self._packs
            if pack.assurance_auditor is not None
            for issue in pack.assurance_auditor.audit(snapshot, config)
        )
        if extension_assurance:
            assurance = replace(
                assurance,
                issues=tuple(sorted(set((*assurance.issues, *extension_assurance)))),
            )
        report = build_run_report(
            snapshot=snapshot,
            engine_version=__version__,
            decision_digest=build_decision_digest(
                config, self._registry, self._adapter.identity, self._packs, self._providers
            ),
            diagnostics=processing.diagnostics,
            engine_issues=(
                *discovery.issues,
                *snapshot.issues,
                *policy_result.result.engine_issues,
                *processing.engine_issues,
                *ignore_result.issues,
            ),
            coverage=policy_result.result.coverage,
            ignore_audit=processing.ignore_audit,
            approval_audit=processing.approval_audit,
            assurance=assurance,
            enforce_assurance=config.strict,
        )
        rendered = (
            render_json(report)
            if request.output_format == "json"
            else render_text(
                report,
                show_inactive=request.show_inactive,
                verbose=request.verbose,
                color=request.use_color,
                width=request.width,
            )
        )
        _timed(timings, "reporting", started)

        self._prior_provider_snapshot = snapshot
        self._prior_policy_context = context
        self._prior_policy_result = policy_result
        counters = CheckCounters(
            reparsed_modules=self._analyzer.reparsed_modules,
            reused_modules=len(snapshot.modules) - self._analyzer.reparsed_modules,
            recomputed_providers=recomputed_providers,
            reused_providers=reused_providers,
            recomputed_evaluations=policy_result.state.evaluated_evaluations,
            reused_evaluations=policy_result.state.reused_evaluations,
            full_policy_rerun=policy_result.state.full_rerun,
        )
        return CheckResult(
            stdout=(rendered + "\n").encode(),
            stderr=b"",
            exit_code=report.exit_decision.code,
            report=report,
            findings=policy_result.result.findings,
            coverage=policy_result.result.coverage,
            issues=report.engine_issues,
            timings=tuple(timings),
            counters=counters,
        )


class _DiskModuleCache:
    def __init__(
        self,
        store: CacheStore,
        adapter: AdapterIdentity,
        resolver_identity: str,
        project_root: Path,
    ) -> None:
        self._store = store
        self._adapter = adapter
        self._resolver_identity = resolver_identity
        self._bundle_context = cache_signing_context(
            (
                "module-bundle:1",
                str(project_root.resolve()),
                adapter.name,
                adapter.version,
                resolver_identity,
            )
        )
        self._bundle_key = hashlib.sha256(self._bundle_context).hexdigest()
        self._sources: tuple[SourceInput, ...] = ()
        self._cached: tuple[ModuleAnalysisResult | None, ...] = ()
        self._bundle_present = False

    def get_many(self, sources: tuple[SourceInput, ...]) -> tuple[ModuleAnalysisResult | None, ...]:
        self._sources = sources
        if not self._store.authenticated:
            self._cached = self._store.get_modules(tuple(self._key(source) for source in sources))
            return self._cached
        bundle = self._store.get_module_bundle(self._bundle_key, context=self._bundle_context)
        self._bundle_present = bundle is not None
        if bundle is None:
            individual = self._store.get_modules(tuple(self._key(source) for source in sources))
            if any(result is not None for result in individual):
                self._cached = individual
                return self._cached
        indexed: dict[str, tuple[str, ModuleAnalysisResult]] = {}
        if bundle is not None:
            for module_identity, source_hash, result in bundle.entries:
                if module_identity in indexed:
                    indexed.clear()
                    self._bundle_present = False
                    break
                indexed[module_identity] = (source_hash, result)
        values: list[ModuleAnalysisResult | None] = []
        for source in sources:
            entry = indexed.get(source.module_id.value)
            if (
                entry is None
                or entry[0] != source.content_hash
                or entry[1].facts.module.id != source.module_id
            ):
                values.append(None)
            else:
                values.append(entry[1])
        self._cached = tuple(values)
        return self._cached

    def put_many(self, entries: tuple[tuple[SourceInput, ModuleAnalysisResult], ...]) -> None:
        if not self._store.authenticated:
            self._store.put_modules(
                tuple((self._key(source), result) for source, result in entries)
            )
            return
        fresh = {source.module_id: result for source, result in entries}
        refresh_threshold = max(32, len(self._sources) // 4)
        if self._bundle_present and len(entries) < refresh_threshold:
            return
        combined: list[tuple[str, str, ModuleAnalysisResult]] = []
        for source, cached in zip(self._sources, self._cached, strict=True):
            result = fresh.get(source.module_id, cached)
            if result is None or result.facts.module.id != source.module_id:
                return
            combined.append((source.module_id.value, source.content_hash, result))
        stored = self._store.put_module_bundle(
            self._bundle_key,
            ModuleBundle(tuple(combined)),
            context=self._bundle_context,
        )
        if not stored:
            self._store.put_modules(
                tuple((self._key(source), result) for source, result in entries)
            )

    def _key(self, source: SourceInput) -> CacheKey:
        return CacheKey(
            source.content_hash,
            self._adapter,
            self._resolver_identity,
            source.module_id.value,
        )


def run_check_request(
    request: CheckRequest,
    module_store: CacheStore | None = None,
    runtime: CheckRuntime | None = None,
) -> CheckResult:
    """Run a single check through the same pipeline used by resident sessions."""
    with ResidentCheckSession(request.project_root, module_store) as session:
        return session.check(request, runtime)


def _timed(values: list[StageTiming], name: str, started: float) -> None:
    values.append(StageTiming(name, (time.perf_counter() - started) * 1000.0))


def _analysis_workers(source_count: int) -> int:
    if source_count < _MINIMUM_PARALLEL_SOURCES:
        return 1
    available = os.cpu_count() or 1
    return max(1, min(available, _MAXIMUM_ANALYSIS_WORKERS, source_count))


def _context_manager_item_type(symbol: SymbolId) -> SymbolId:
    if symbol.value.startswith("tortoise."):
        return _TORTOISE_CONNECTION_TYPE
    return _ASYNC_SESSION_TYPE
