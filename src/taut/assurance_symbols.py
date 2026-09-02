from __future__ import annotations

from taut.configuration.assurance import FeatureExpectation
from taut.configuration.model import ProjectConfiguration
from taut.domain.assurance import AssuranceIssue
from taut.domain.ids import SymbolId
from taut.domain.snapshot import AnalysisSnapshot


def same_symbol(left: SymbolId, right: SymbolId) -> bool:
    """Compare policy symbols exactly after the analyzer has resolved aliases."""
    return left == right


def policy_symbol_issues(
    config: ProjectConfiguration, snapshot: AnalysisSnapshot
) -> tuple[AssuranceIssue, ...]:
    required = {
        name
        for name, expectation in config.assurance.features.items()
        if expectation is FeatureExpectation.REQUIRED
    }
    code = config.policy.code
    policy = config.policy
    configured: list[tuple[str, SymbolId, str]] = []
    if "schema" in required:
        configured.extend(("schema config", item, "value") for item in code.request_config_symbols)
        configured.extend(("schema config", item, "value") for item in code.response_config_symbols)
    if "dto" in required:
        configured.extend(("DTO base", item, "class") for item in code.dto_base_symbols)
    if "exception_registry" in required:
        configured.extend(("exception base", item, "class") for item in code.exception_base_symbols)
        configured.extend(
            ("error code enum", item, "class") for item in code.error_code_enum_symbols
        )
    if "transaction" in required:
        configured.extend(
            ("transaction provider", item, "callable")
            for item in policy.transaction_session_providers
        )
        configured.extend(
            ("transaction decorator", item, "callable")
            for item in policy.transaction_boundary_decorators
        )
    if "external_calls" in required:
        configured.extend(
            ("external wrapper", item, "callable")
            for item in policy.boundaries.external_call_wrappers
        )

    top_levels = {module_id.value.split(".", 1)[0] for module_id in snapshot.modules}
    classes = {item.symbol_id for module in snapshot.modules.values() for item in module.classes}
    functions = {
        item.symbol_id for module in snapshot.modules.values() for item in module.functions
    }
    fields = {item.symbol_id for module in snapshot.modules.values() for item in module.fields}
    observed = (
        classes
        | functions
        | fields
        | {
            ref.symbol
            for module in snapshot.modules.values()
            for call in module.calls
            for ref in (call.ref, *call.enclosing_contexts)
            if ref.symbol is not None
        }
        | {
            decorator.ref.symbol
            for module in snapshot.modules.values()
            for decorator in module.decorators
            if decorator.ref.symbol is not None
        }
    )
    issues: list[AssuranceIssue] = []
    for label, symbol, expected_kind in configured:
        if symbol not in observed:
            issues.append(
                AssuranceIssue(
                    "POLICY_SYMBOL_UNRESOLVED",
                    "정책 활성화에 사용한 exact symbol을 실제 코드에서 확인하지 못했습니다.",
                    symbol.value,
                    f"{label} 설정을 실제 fully-qualified symbol로 수정하세요.",
                )
            )
            continue
        if symbol.value.split(".", 1)[0] not in top_levels:
            continue
        correct = (
            symbol in classes
            if expected_kind == "class"
            else symbol in fields
            if expected_kind == "value"
            else symbol in functions or symbol in classes
        )
        if not correct:
            issues.append(
                AssuranceIssue(
                    "POLICY_SYMBOL_KIND_MISMATCH",
                    "정책 symbol의 실제 종류가 요구한 계약과 다릅니다.",
                    symbol.value,
                    f"{label}에는 {expected_kind} symbol을 지정하세요.",
                )
            )
    return tuple(issues)
