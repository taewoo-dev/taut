from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path

from taut.analysis.framework.fastapi import FASTAPI_ENDPOINTS, FASTAPI_ROUTERS
from taut.analysis.framework.pydantic import PYDANTIC_MODELS
from taut.analysis.framework.sqlalchemy import (
    SQLALCHEMY_MODELS,
    SQLALCHEMY_QUERIES,
    SQLALCHEMY_RAW_SQL,
    SQLALCHEMY_SESSIONS,
    SQLALCHEMY_TRANSACTIONS,
)
from taut.analysis.framework.tortoise import (
    TORTOISE_CONNECTIONS,
    TORTOISE_MODELS,
    TORTOISE_QUERIES,
    TORTOISE_RAW_SQL,
    TORTOISE_TRANSACTIONS,
)
from taut.assurance_evidence import FeatureEvidenceCache
from taut.assurance_roles import semantic_role_issues
from taut.assurance_symbols import policy_symbol_issues, same_symbol
from taut.configuration.assurance import FeatureExpectation
from taut.configuration.manifest import ClassificationIndex
from taut.configuration.model import ProjectConfiguration
from taut.domain.assurance import (
    AssuranceEvidence,
    AssuranceIssue,
    AssuranceReport,
    FeatureAssurance,
)
from taut.domain.snapshot import AnalysisSnapshot
from taut.loading.source_discovery import SourceDiscoveryResult
from taut.onboarding_contributors import onboarding_framework_specs
from taut.project_observation import python_files


def audit_project_assurance(
    project_root: Path,
    config: ProjectConfiguration,
    discovery: SourceDiscoveryResult,
    snapshot: AnalysisSnapshot,
    classifications: ClassificationIndex,
    *,
    used_approvals: int,
    used_ignores: int,
    unused_approvals: tuple[str, ...] = (),
    evidence_cache: FeatureEvidenceCache | None = None,
) -> AssuranceReport:
    all_python = _project_python_files(project_root, config.force_include)
    analyzed = frozenset(source.path.value for source in discovery.sources)
    accounted = analyzed.union(
        entry.path.value for entry in discovery.report.entries if entry.reason == "shadowed_stub"
    )
    excluded, unused_exclusions = _reasoned_exclusions(all_python, config)
    issues: list[AssuranceIssue] = []

    for path in sorted(all_python.difference(accounted).difference(excluded)):
        issues.append(
            _issue(
                "SOURCE_UNACCOUNTED",
                "Python file is neither analyzed nor covered by a reasoned exclusion.",
                path,
                (
                    "Include it in include/source_roots or provide a reason in "
                    "[[tool.taut.exclusions]]."
                ),
            )
        )
    for pattern in unused_exclusions:
        issues.append(
            _issue(
                "EXCLUSION_UNUSED",
                "Reasoned exclusion pattern matches no Python files.",
                pattern,
                "Remove the stale exclusion or update it to match an existing path.",
            )
        )

    analyzed_paths = tuple(sorted(analyzed))
    for matcher in config.manifest.roles:
        matched = tuple(
            path
            for path in analyzed_paths
            if any(fnmatchcase(path, pattern) for pattern in matcher.patterns)
            and not any(fnmatchcase(path, pattern) for pattern in matcher.exclude)
        )
        if not matched:
            issues.append(
                _issue(
                    "ROLE_SELECTOR_UNUSED",
                    "Role pattern matches no analyzed files.",
                    matcher.role.value,
                    f"Update the tool.taut.roles.{matcher.role.value} pattern or remove the role.",
                )
            )
    for zone_matcher in config.manifest.zones:
        if not any(
            any(fnmatchcase(path, pattern) for pattern in zone_matcher.patterns)
            for path in analyzed_paths
        ):
            issues.append(
                _issue(
                    "ZONE_SELECTOR_UNUSED",
                    "Zone pattern matches no analyzed files.",
                    zone_matcher.zone.value,
                    f"Update the tool.taut.zones.{zone_matcher.zone.value} pattern or "
                    "remove the zone.",
                )
            )
    for module_id, classification in classifications.modules.items():
        if classification.role is None:
            path = snapshot.modules[module_id].module.path.value
            issues.append(
                _issue(
                    "ROLE_UNCLASSIFIED",
                    "Analyzed module has no architecture role.",
                    path,
                    "Place code in the declared role location and align its responsibilities. "
                    "Change conventions only when introducing a new architecture. "
                    + config.manifest.placement_hint(),
                )
            )

    issues.extend(
        semantic_role_issues(snapshot, classifications, config.policy.code, config.manifest)
    )

    framework_providers = {
        root: spec.provider_id
        for spec in onboarding_framework_specs()
        for root in spec.import_roots
    }
    configured_providers = set(config.providers)
    imported_frameworks = {
        framework
        for module in snapshot.modules.values()
        for imported in module.imports
        for framework in framework_providers
        if imported.imported_module_name == framework
        or imported.imported_module_name.startswith(f"{framework}.")
    }
    for framework in sorted(imported_frameworks):
        provider = framework_providers[framework]
        if provider not in configured_providers:
            issues.append(
                _issue(
                    "FRAMEWORK_PROVIDER_MISSING",
                    "No semantic provider is configured for a framework in use.",
                    framework,
                    f"Add {provider} to tool.taut.providers.",
                )
            )

    raw_evidence = _feature_evidence(config, snapshot, classifications, evidence_cache)
    issues.extend(policy_symbol_issues(config, snapshot))
    filtered, used_assertions = _apply_assertions(raw_evidence, config)
    feature_reports: list[FeatureAssurance] = []
    for name, expectation in config.assurance.features.items():
        evidence = tuple(sorted(filtered.get(name, ())))
        detected = bool(evidence)
        feature_reports.append(FeatureAssurance(name, expectation.value, detected, evidence))
        if expectation is FeatureExpectation.REQUIRED and not detected:
            issues.append(
                _issue(
                    "FEATURE_REQUIRED_MISSING",
                    "No source evidence was found for a feature declared required.",
                    name,
                    f"Check tool.taut.assurance.features.{name} "
                    "and the associated role and symbol settings.",
                )
            )
        if expectation is FeatureExpectation.ABSENT and detected:
            first = evidence[0]
            issues.append(
                _issue(
                    "FEATURE_ABSENT_DETECTED",
                    "Source evidence was found for a feature declared absent.",
                    f"{name}:{first.target}",
                    f"Set {name} to required and configure its policy, or "
                    "provide a reason in an exact assertion.",
                )
            )
        if expectation is FeatureExpectation.REQUIRED and detected:
            issues.extend(_activation_issues(name, config, classifications, snapshot))

    for assertion in config.assurance.assertions:
        key = _assertion_key(assertion.domain, assertion.kind, assertion.target)
        if key not in used_assertions:
            issues.append(
                _issue(
                    "ASSERTION_UNUSED",
                    "Assurance assertion no longer matches any source evidence.",
                    key,
                    "Remove the stale assertion or update it to the exact target.",
                )
            )
    if used_approvals > config.assurance.max_approvals:
        issues.append(
            _issue(
                "APPROVAL_BUDGET_EXCEEDED",
                "Used approvals exceed the strict assurance budget.",
                str(used_approvals),
                "Remove approvals or explicitly adjust max_approvals.",
            )
        )
    for approval in unused_approvals:
        issues.append(
            _issue(
                "APPROVAL_UNUSED",
                "Approval is not used by any current violation or explicit participation contract.",
                approval,
                "Remove the stale approval or update its exact rule, symbol, and target.",
            )
        )
    if used_ignores > config.assurance.max_inline_ignores:
        issues.append(
            _issue(
                "IGNORE_BUDGET_EXCEEDED",
                "Used inline ignores exceed the strict assurance budget.",
                str(used_ignores),
                "Remove inline ignores or explicitly adjust max_inline_ignores.",
            )
        )
    return AssuranceReport(
        discovered_python_files=len(all_python),
        analyzed_python_files=len(analyzed),
        excluded_python_files=len(excluded),
        features=tuple(feature_reports),
        issues=tuple(sorted(set(issues))),
        used_assertions=tuple(sorted(used_assertions)),
    )


def _project_python_files(
    project_root: Path, force_include: tuple[str, ...] = ()
) -> frozenset[str]:
    return frozenset(python_files(project_root, force_include))


def _reasoned_exclusions(
    paths: frozenset[str], config: ProjectConfiguration
) -> tuple[frozenset[str], tuple[str, ...]]:
    excluded: set[str] = set()
    unused: list[str] = []
    for item in config.assurance.exclusions:
        for pattern in item.patterns:
            matched = {path for path in paths if fnmatchcase(path, pattern)}
            if not matched:
                unused.append(pattern)
            excluded.update(matched)
    return frozenset(excluded), tuple(sorted(unused))


def _feature_evidence(
    config: ProjectConfiguration,
    snapshot: AnalysisSnapshot,
    classifications: ClassificationIndex,
    evidence_cache: FeatureEvidenceCache | None = None,
) -> dict[str, set[AssuranceEvidence]]:
    values = {name: set[AssuranceEvidence]() for name in config.assurance.features}

    def add(domain: str, kind: str, target: str, path: str) -> None:
        if domain in values:
            values[domain].add(AssuranceEvidence(domain, kind, target, path))

    for capability in (FASTAPI_ENDPOINTS, FASTAPI_ROUTERS):
        for fact in snapshot.capabilities.get(capability, ()):
            module_id = getattr(fact, "module_id", None)
            if module_id is not None and module_id in snapshot.modules:
                path = snapshot.modules[module_id].module.path.value
                add("api", "path", path, path)
    for fact in snapshot.capabilities.get(PYDANTIC_MODELS, ()):
        module_id = getattr(fact, "module_id", None)
        symbol_id = getattr(fact, "symbol_id", None)
        if module_id is not None and module_id in snapshot.modules:
            path = snapshot.modules[module_id].module.path.value
            add("schema", "symbol", str(symbol_id or module_id), path)
    for capability in (
        SQLALCHEMY_MODELS,
        SQLALCHEMY_QUERIES,
        SQLALCHEMY_RAW_SQL,
        SQLALCHEMY_SESSIONS,
        TORTOISE_MODELS,
        TORTOISE_QUERIES,
        TORTOISE_CONNECTIONS,
        TORTOISE_RAW_SQL,
    ):
        for fact in snapshot.capabilities.get(capability, ()):
            module_id = getattr(fact, "module_id", None)
            if module_id is not None and module_id in snapshot.modules:
                path = snapshot.modules[module_id].module.path.value
                add("database", "path", path, path)
    for capability in (SQLALCHEMY_TRANSACTIONS, TORTOISE_TRANSACTIONS):
        for fact in snapshot.capabilities.get(capability, ()):
            module_id = getattr(fact, "module_id", None)
            if module_id is not None and module_id in snapshot.modules:
                path = snapshot.modules[module_id].module.path.value
                add("transaction", "path", path, path)

    current_cache = evidence_cache if evidence_cache is not None else FeatureEvidenceCache()
    for module_id in tuple(current_cache.entries):
        if module_id not in snapshot.modules:
            del current_cache.entries[module_id]
    for module_id, module in snapshot.modules.items():
        evidence = current_cache.collect(config, module, classifications.modules.get(module_id))
        for name, items in evidence.items():
            values[name].update(items)
    return values


def _apply_assertions(
    evidence: dict[str, set[AssuranceEvidence]], config: ProjectConfiguration
) -> tuple[dict[str, set[AssuranceEvidence]], set[str]]:
    filtered = {name: set(items) for name, items in evidence.items()}
    used: set[str] = set()
    for assertion in config.assurance.assertions:
        for item in tuple(filtered.get(assertion.domain, ())):
            actual = item.path if assertion.kind == "path" else item.target
            if actual != assertion.target:
                continue
            filtered[assertion.domain].remove(item)
            used.add(_assertion_key(assertion.domain, assertion.kind, assertion.target))
    return filtered, used


def _assertion_key(domain: str, kind: str, target: str) -> str:
    return f"{domain}:{kind}:{target}"


def _activation_issues(
    domain: str,
    config: ProjectConfiguration,
    classifications: ClassificationIndex,
    snapshot: AnalysisSnapshot,
) -> tuple[AssuranceIssue, ...]:
    roles = {item.role for item in classifications.modules.values() if item.role is not None}
    code = config.policy.code
    active = True
    key = ""
    if domain == "api":
        active = bool(roles.intersection(code.router_roles))
        key = "layers.entry/code_conventions.router_roles"
    elif domain == "schema":
        active = bool(roles.intersection(code.schema_roles)) and bool(
            code.request_config_symbols or code.response_config_symbols
        )
        key = "code_conventions.schema_roles/request_config_symbols/response_config_symbols"
    elif domain == "dto":
        active = bool(roles.intersection(code.dto_roles) or code.dto_base_symbols)
        key = "code_conventions.dto_roles/dto_base_symbols"
    elif domain == "snapshot":
        active = bool(roles.intersection(code.snapshot_roles))
        key = "code_conventions.snapshot_roles"
    elif domain == "exception_registry":
        active = bool(code.exception_base_symbols) and bool(code.error_code_enum_symbols)
        key = "code_conventions.exception_base_symbols/error_code_enum_symbols"
    elif domain == "enum":
        active, key = bool(code.shared_enum_modules), "enum.shared_modules"
    elif domain == "database":
        active = bool(roles.intersection(code.model_roles))
        key = "layers.model/code_conventions.model_roles"
    elif domain == "transaction":
        active = bool(config.policy.transaction_owner_roles) and bool(
            config.policy.transaction_session_providers
            or config.policy.transaction_boundary_decorators
            or config.policy.transaction_boundary_contexts
        )
        if active:
            transaction_symbols = config.policy.transaction_session_providers.union(
                config.policy.transaction_boundary_decorators
            ).union(config.policy.transaction_boundary_contexts)
            active = any(
                decorator.ref.symbol is not None
                and any(same_symbol(decorator.ref.symbol, item) for item in transaction_symbols)
                for module in snapshot.modules.values()
                for decorator in module.decorators
            ) or any(
                call.ref.symbol is not None
                and any(same_symbol(call.ref.symbol, item) for item in transaction_symbols)
                for module in snapshot.modules.values()
                for call in module.calls
            )
        key = "transaction.owner_roles/session_providers/boundary_decorators/boundary_contexts"
    elif domain == "external_calls":
        # A wrapper is an optional approved boundary, not a prerequisite for LOG001:
        # projects without one must receive actionable rule failures instead of being
        # forced to invent a configuration symbol merely to complete assurance.
        active = True
    elif domain == "tests":
        active = any(item.zone.value == "test" for item in classifications.modules.values())
        key = "zones.test"
    elif domain == "migrations":
        active, key = (
            any(item.zone.value == "migration" for item in classifications.modules.values()),
            "zones.migration",
        )
    elif domain == "scripts":
        active = any(item.zone.value == "script" for item in classifications.modules.values())
        key = "zones.script"
    if active:
        return ()
    return (
        _issue(
            "FEATURE_POLICY_INACTIVE",
            "A required feature has source evidence, but its role, symbol, or zone settings "
            "are not active.",
            domain,
            f"Connect tool.taut.{key} settings to the actual source code.",
        ),
    )


def _issue(code: str, message: str, subject: str, remediation: str) -> AssuranceIssue:
    return AssuranceIssue(code, message, subject, remediation)
