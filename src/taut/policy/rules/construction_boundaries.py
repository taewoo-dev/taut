from __future__ import annotations

from taut.configuration.manifest import Zone
from taut.domain.evaluations import ChangeImpact, RuleTarget, RuleTargetRef, RuleVerdict
from taut.domain.facts import AnalysisStage, ExpressionSummary
from taut.domain.findings import Finding
from taut.domain.ids import ModuleId, RuleId, SymbolId
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import (
    derived_fact_uncertainty,
    module_fact_uncertainty,
    unresolved_call_evaluation,
)
from taut.policy.rules.layer_boundaries import (
    RULE_VERSION,
    boundary_result,
    build_boundary_finding,
    matches_module_prefix,
)

WIRING_RULE_ID = RuleId("WIRING001")
ADAPTER_TYPE_RULE_ID = RuleId("ADAPTER002")
CONFIG_RULE_ID = RuleId("CONFIG001")

_ALL_ZONES = frozenset({Zone("prod"), Zone("test"), Zone("migration"), Zone("script")})


class ImplementationConstructionRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("WIRING001 requires a module target")
        uncertainty = module_fact_uncertainty(WIRING_RULE_ID, target, context, target.module_id)
        if uncertainty is not None:
            return uncertainty
        role = context.classification.get(target.module_id).role
        if role is None:
            return RuleEvaluation(WIRING_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        boundaries = context.policy.boundaries
        constructors = context.indexes.adapter_implementation_symbols.union(
            boundaries.external_client_constructors
        )
        allowed_roles = boundaries.bootstrap_roles.union(
            boundaries.implementation_construction_roles
        )
        uncertainty = unresolved_call_evaluation(
            WIRING_RULE_ID, target, context, target.module_id, tuple(constructors)
        )
        if uncertainty is not None:
            return uncertainty
        findings: list[Finding] = []
        for call in context.model.calls_in(target.module_id):
            symbol = call.ref.symbol
            if symbol is None or symbol not in constructors or role in allowed_roles:
                continue
            findings.append(
                build_boundary_finding(
                    WIRING_RULE_ID,
                    module_id=target.module_id,
                    subject=call.id,
                    enclosing_symbol=call.enclosing_symbol,
                    location=call.location,
                    message_key="wiring.constructor_outside_bootstrap",
                    kind="constructor",
                    value=symbol.value,
                )
            )
        return boundary_result(WIRING_RULE_ID, target, findings)


def _external_annotation(
    expression: ExpressionSummary | None,
    external_modules: tuple[ModuleId, ...],
) -> SymbolId | None:
    if expression is None:
        return None
    return next(
        (
            symbol
            for symbol in expression.symbols
            if matches_module_prefix(symbol.value, external_modules) is not None
        ),
        None,
    )


class AdapterTypeLeakRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("ADAPTER002 requires a module target")
        uncertainty = derived_fact_uncertainty(
            ADAPTER_TYPE_RULE_ID, target, context, target.module_id
        )
        if uncertainty is not None:
            return uncertainty
        role = context.classification.get(target.module_id).role
        boundaries = context.policy.boundaries
        if role is None or role not in boundaries.adapter_roles:
            return RuleEvaluation(ADAPTER_TYPE_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        findings: list[Finding] = []
        for function in context.model.module(target.module_id).functions:
            if function.name.startswith("_"):
                continue
            annotations = (
                *(parameter.annotation for parameter in function.parameters),
                function.return_annotation,
            )
            leaked = next(
                (
                    symbol
                    for annotation in annotations
                    if (symbol := _external_annotation(annotation, boundaries.external_modules))
                    is not None
                ),
                None,
            )
            if leaked is None:
                continue
            findings.append(
                build_boundary_finding(
                    ADAPTER_TYPE_RULE_ID,
                    module_id=target.module_id,
                    subject=function.id,
                    enclosing_symbol=function.symbol_id,
                    location=function.location,
                    message_key="adapter.external_type_leak",
                    kind="external_type",
                    value=leaked.value,
                )
            )
        return boundary_result(ADAPTER_TYPE_RULE_ID, target, findings)


class SettingsConstructionRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("CONFIG001 requires a module target")
        uncertainty = module_fact_uncertainty(CONFIG_RULE_ID, target, context, target.module_id)
        if uncertainty is not None:
            return uncertainty
        role = context.classification.get(target.module_id).role
        if role is None:
            return RuleEvaluation(CONFIG_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        boundaries = context.policy.boundaries
        settings_classes = context.indexes.settings_constructor_symbols
        if not settings_classes:
            return RuleEvaluation(CONFIG_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        uncertainty = unresolved_call_evaluation(
            CONFIG_RULE_ID, target, context, target.module_id, tuple(settings_classes)
        )
        if uncertainty is not None:
            return uncertainty
        allowed = boundaries.configuration_roles.union(boundaries.bootstrap_roles)
        findings: list[Finding] = []
        for call in context.model.calls_in(target.module_id):
            symbol = call.ref.symbol
            if symbol is None or symbol not in settings_classes or role in allowed:
                continue
            findings.append(
                build_boundary_finding(
                    CONFIG_RULE_ID,
                    module_id=target.module_id,
                    subject=call.id,
                    enclosing_symbol=call.enclosing_symbol,
                    location=call.location,
                    message_key="config.settings_construction",
                    kind="settings",
                    value=symbol.value,
                )
            )
        return boundary_result(CONFIG_RULE_ID, target, findings)


def construction_rule_definitions() -> tuple[RuleDefinition, ...]:
    requirements = RuleRequirements(frozenset(), AnalysisStage.FACTS_READY, False, False)
    return (
        RuleDefinition(
            WIRING_RULE_ID,
            RULE_VERSION,
            "구현과 client 생성 위치",
            "외부 client와 Adapter 구현은 시작 조립 코드 또는 승인된 Factory에서만 만드세요.",
            RuleTarget.MODULE,
            requirements,
            ChangeImpact.SELF,
            ImplementationConstructionRule(),
            ("tests/fixtures/rules/wiring/compliant.py",),
            ("tests/fixtures/rules/wiring/violation.py",),
            applies_to_zones=_ALL_ZONES,
        ),
        RuleDefinition(
            ADAPTER_TYPE_RULE_ID,
            RULE_VERSION,
            "Adapter 외부 자료형 유출 금지",
            "Adapter의 공개 입력과 반환형은 내부 자료형만 사용하세요.",
            RuleTarget.MODULE,
            requirements,
            ChangeImpact.SELF,
            AdapterTypeLeakRule(),
            ("tests/fixtures/rules/adapter_type/compliant.py",),
            ("tests/fixtures/rules/adapter_type/violation.py",),
            applies_to_zones=_ALL_ZONES,
        ),
        RuleDefinition(
            CONFIG_RULE_ID,
            RULE_VERSION,
            "Settings 생성 위치",
            "Settings는 설정 또는 시작 조립 코드에서만 만들고 "
            "나머지는 승인된 접근 함수를 사용하세요.",
            RuleTarget.MODULE,
            requirements,
            ChangeImpact.SELF,
            SettingsConstructionRule(),
            ("tests/fixtures/rules/settings/compliant.py",),
            ("tests/fixtures/rules/settings/violation.py",),
            applies_to_zones=_ALL_ZONES,
        ),
    )
