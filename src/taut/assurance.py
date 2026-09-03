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
) -> AssuranceReport:
    all_python = _project_python_files(project_root)
    analyzed = frozenset(source.path.value for source in discovery.sources)
    excluded, unused_exclusions = _reasoned_exclusions(all_python, config)
    issues: list[AssuranceIssue] = []

    for path in sorted(all_python.difference(analyzed).difference(excluded)):
        issues.append(
            _issue(
                "SOURCE_UNACCOUNTED",
                "Python 파일이 분석되거나 사유 있는 제외로 등록되지 않았습니다.",
                path,
                "include/source_roots에 포함하거나 [[tool.taut.exclusions]]에 사유를 적으세요.",
            )
        )
    for pattern in unused_exclusions:
        issues.append(
            _issue(
                "EXCLUSION_UNUSED",
                "사유 있는 제외 패턴이 어떤 Python 파일과도 일치하지 않습니다.",
                pattern,
                "오래된 제외를 제거하거나 실제 경로로 수정하세요.",
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
                    "role 패턴이 분석된 파일을 하나도 분류하지 못했습니다.",
                    matcher.role.value,
                    f"tool.taut.roles.{matcher.role.value} 패턴을 수정하거나 role을 제거하세요.",
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
                    "zone 패턴이 분석된 파일을 하나도 분류하지 못했습니다.",
                    zone_matcher.zone.value,
                    f"tool.taut.zones.{zone_matcher.zone.value} 패턴을 수정하거나 "
                    "zone을 제거하세요.",
                )
            )
    for module_id, classification in classifications.modules.items():
        if classification.role is None:
            path = snapshot.modules[module_id].module.path.value
            issues.append(
                _issue(
                    "ROLE_UNCLASSIFIED",
                    "분석된 모듈에 architecture role이 없습니다.",
                    path,
                    "tool.taut.roles와 tool.taut.allow에 이 모듈의 역할을 선언하세요.",
                )
            )

    framework_providers = {
        "fastapi": "taut.fastapi",
        "pydantic": "taut.pydantic",
        "pytest": "taut.pytest",
        "sqlalchemy": "taut.sqlalchemy",
        "tortoise": "taut.tortoise",
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
                    "사용 중인 프레임워크의 semantic provider가 설정되지 않았습니다.",
                    framework,
                    f"tool.taut.providers에 {provider}를 추가하세요.",
                )
            )

    raw_evidence = _feature_evidence(config, snapshot, classifications)
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
                    "required로 선언한 정책 영역의 실제 코드 근거를 찾지 못했습니다.",
                    name,
                    f"tool.taut.assurance.features.{name} 또는 관련 역할·심볼 설정을 확인하세요.",
                )
            )
        if expectation is FeatureExpectation.ABSENT and detected:
            first = evidence[0]
            issues.append(
                _issue(
                    "FEATURE_ABSENT_DETECTED",
                    "absent로 선언한 정책 영역의 코드 근거가 발견됐습니다.",
                    f"{name}:{first.target}",
                    f"{name}을 required로 바꾸고 관련 정책을 설정하거나 "
                    "exact assertion에 사유를 적으세요.",
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
                    "assurance assertion이 더 이상 어떤 코드 근거와도 일치하지 않습니다.",
                    key,
                    "오래된 assertion을 제거하거나 정확한 target으로 수정하세요.",
                )
            )
    if used_approvals > config.assurance.max_approvals:
        issues.append(
            _issue(
                "APPROVAL_BUDGET_EXCEEDED",
                "사용된 approval 수가 strict assurance 예산을 초과했습니다.",
                str(used_approvals),
                "approval을 제거하거나 max_approvals를 의도적으로 조정하세요.",
            )
        )
    if used_ignores > config.assurance.max_inline_ignores:
        issues.append(
            _issue(
                "IGNORE_BUDGET_EXCEEDED",
                "사용된 inline ignore 수가 strict assurance 예산을 초과했습니다.",
                str(used_ignores),
                "inline ignore를 제거하거나 max_inline_ignores를 의도적으로 조정하세요.",
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


def _project_python_files(project_root: Path) -> frozenset[str]:
    return frozenset(python_files(project_root))


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

    code = config.policy.code
    for module_id, module in snapshot.modules.items():
        path = module.module.path.value
        classification = classifications.modules.get(module_id)
        role = classification.role if classification is not None else None
        zone = classification.zone.value if classification is not None else "prod"
        if zone == "test":
            add("tests", "path", path, path)
        elif zone == "migration":
            add("migrations", "path", path, path)
        elif zone == "script":
            add("scripts", "path", path, path)
        if module.classes and role in code.dto_roles:
            add("dto", "path", path, path)
        if module.classes and role in code.snapshot_roles:
            add("snapshot", "path", path, path)
        if module.classes and role in code.model_roles:
            add("database", "path", path, path)
        for class_fact in module.classes:
            bases = {
                value
                for base in class_fact.bases
                for value in (base.written, *(symbol.value for symbol in base.symbols))
            }
            symbol = class_fact.symbol_id.value
            if any(base in {"pydantic.BaseModel", "pydantic.main.BaseModel"} for base in bases):
                add("schema", "symbol", symbol, path)
            if "Snapshot" in class_fact.name and any(
                base in {"pydantic.BaseModel", "pydantic.main.BaseModel"} for base in bases
            ):
                add("snapshot", "symbol", symbol, path)
            if any(base.endswith("Exception") or base.endswith("Error") for base in bases):
                add("exception_registry", "symbol", symbol, path)
            if class_fact.symbol_id in (code.exception_base_symbols | code.error_code_enum_symbols):
                add("exception_registry", "symbol", symbol, path)
            if any(base.endswith(".Enum") or base.endswith(".StrEnum") for base in bases):
                add("enum", "symbol", symbol, path)
        for decorator in module.decorators:
            decorator_symbol = decorator.ref.symbol
            if decorator_symbol is not None and decorator_symbol.value == "dataclasses.dataclass":
                owner = decorator.decorated_symbol.value
                if owner.endswith(("Data", "Result", "Row")):
                    add("dto", "symbol", owner, path)
        for call in module.calls:
            call_symbol = (
                call.ref.symbol.value if call.ref.symbol is not None else call.ref.written_name
            )
            if call_symbol.endswith((".commit", ".rollback", ".begin")):
                add("transaction", "symbol", call_symbol, path)
            if any(
                call_symbol == prefix.value or call_symbol.startswith(f"{prefix.value}.")
                for prefix in config.policy.boundaries.external_modules
            ):
                add("external_calls", "symbol", call_symbol, path)
            if call_symbol in {"os.getenv", "os.environ.get"} or any(
                call_symbol.startswith(prefix)
                for prefix in config.policy.security.risky_symbol_prefixes
            ):
                add("security", "symbol", call_symbol, path)
        for reference in module.references:
            reference_symbol = (
                reference.ref.symbol.value
                if reference.ref.symbol is not None
                else reference.ref.written_name
            )
            if reference_symbol in {"os.environ", "os.getenv"}:
                add("security", "symbol", reference_symbol, path)
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
    boundaries = config.policy.boundaries
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
        )
        if active:
            transaction_symbols = config.policy.transaction_session_providers.union(
                config.policy.transaction_boundary_decorators
            )
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
        key = "transaction.owner_roles/session_providers/boundary_decorators"
    elif domain == "external_calls":
        active = bool(boundaries.logged_external_calls) and bool(boundaries.external_call_wrappers)
        if active:
            active = any(
                (
                    call.enclosing_symbol is not None
                    and any(
                        same_symbol(call.enclosing_symbol, wrapper)
                        for wrapper in boundaries.external_call_wrappers
                    )
                )
                or any(
                    ref.symbol is not None
                    and any(
                        same_symbol(ref.symbol, wrapper)
                        for wrapper in boundaries.external_call_wrappers
                    )
                    for ref in call.enclosing_contexts
                )
                for module in snapshot.modules.values()
                for call in module.calls
            )
        key = "external.logged_calls/wrappers"
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
            "required 정책 영역의 코드 근거는 있지만 관련 역할·심볼·zone 설정이 "
            "활성화되지 않았습니다.",
            domain,
            f"tool.taut.{key} 설정을 실제 코드에 연결하세요.",
        ),
    )


def _issue(code: str, message: str, subject: str, remediation: str) -> AssuranceIssue:
    return AssuranceIssue(code, message, subject, remediation)
