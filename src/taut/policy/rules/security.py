from __future__ import annotations

from taut.configuration.catalog import AccessPath, Effect, EffectResolutionState
from taut.configuration.manifest import Role, Zone
from taut.domain.evaluations import (
    ChangeImpact,
    EvaluationReason,
    RuleTarget,
    RuleTargetRef,
    RuleVerdict,
)
from taut.domain.facts import AnalysisStage, CallFact, ReferenceFact, ResolutionState
from taut.domain.findings import EvidenceItem, Finding
from taut.domain.ids import RuleId, SymbolId
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import (
    build_finding,
    module_fact_uncertainty,
    unresolved_call_evaluation,
)

RULE_ID = RuleId("SEC001")
RULE_VERSION = 3
_SECURITY_EFFECTS = frozenset(
    {
        Effect.SECURITY_ENVIRONMENT,
        Effect.SECURITY_SECRET,
        Effect.SECURITY_TOKEN,
    }
)
_ALL_ZONES = frozenset({Zone("prod"), Zone("test"), Zone("migration"), Zone("script")})


class DirectSecurityAccessRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("SEC001 requires a module target")
        uncertainty = module_fact_uncertainty(RULE_ID, target, context, target.module_id)
        if uncertainty is not None:
            return uncertainty
        role = context.classification.get(target.module_id).role
        if role is None:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        module = context.model.module(target.module_id)
        security_symbols = tuple(
            symbol
            for symbol, entry in context.catalog.entries.items()
            if entry.effects.intersection(_SECURITY_EFFECTS)
        )
        uncertainty = unresolved_call_evaluation(
            RULE_ID, target, context, target.module_id, security_symbols
        )
        if uncertainty is not None:
            return uncertainty
        findings: list[Finding] = []
        for call in module.calls:
            resolution = context.effect_of(call)
            if resolution.state is not EffectResolutionState.MATCHED:
                continue
            effects = resolution.effects.intersection(_SECURITY_EFFECTS)
            if not effects or resolution.access_path is AccessPath.APPROVED_WRAPPER:
                continue
            if all(_role_allowed(role, effect, context) for effect in effects):
                continue
            findings.append(_call_finding(call, role.value, effects))
        for reference in module.references:
            if reference.ref.state is not ResolutionState.RESOLVED and (
                SymbolId("os.environ") in reference.ref.candidates
            ):
                return RuleEvaluation(
                    RULE_ID,
                    target,
                    RuleVerdict.INDETERMINATE,
                    (),
                    EvaluationReason(
                        "uncertain_symbol",
                        "규칙에 필요한 environment reference를 확정하지 못했습니다.",
                    ),
                )
            if not _is_direct_environ_reference(reference, module.calls):
                continue
            effect = Effect.SECURITY_ENVIRONMENT
            if _role_allowed(role, effect, context):
                continue
            findings.append(_reference_finding(reference, role.value, effect))
        if findings:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(RULE_ID, target, RuleVerdict.PASS, ())


def _role_allowed(role: Role, effect: Effect, context: PolicyContext) -> bool:
    allowed = context.policy.security.allowed_roles.get(effect, frozenset())
    if effect in {Effect.SECURITY_ENVIRONMENT, Effect.SECURITY_SECRET}:
        allowed = allowed.union(context.policy.boundaries.configuration_roles)
        allowed = allowed.union(context.policy.boundaries.bootstrap_roles)
    return role in allowed


def _is_direct_environ_reference(
    reference: ReferenceFact,
    calls: tuple[CallFact, ...],
) -> bool:
    if reference.ref.state is not ResolutionState.RESOLVED:
        return False
    if reference.ref.symbol is None or reference.ref.symbol.value != "os.environ":
        return False
    return not any(
        call.ref.symbol is not None
        and call.ref.symbol.value.startswith("os.environ.")
        and call.location.start_line == reference.location.start_line
        and call.location.start_column <= reference.location.start_column
        and call.location.end_column >= reference.location.end_column
        for call in calls
    )


def _call_finding(call: CallFact, role: str, effects: frozenset[Effect]) -> Finding:
    symbol = call.ref.symbol.value if call.ref.symbol else call.ref.written_name
    return build_finding(
        rule_id=RULE_ID,
        rule_version=RULE_VERSION,
        module_id=call.module_id,
        enclosing_symbol=call.enclosing_symbol,
        subject=call.id,
        normalized_subject=f"{role}:{symbol}:{call.id.value}",
        message_key="security.direct_access",
        arguments=(("role", role), ("call", symbol)),
        location=call.location,
        evidence=(EvidenceItem("effects", tuple(sorted(effect.value for effect in effects))),),
    )


def _reference_finding(reference: ReferenceFact, role: str, effect: Effect) -> Finding:
    symbol = reference.ref.symbol.value if reference.ref.symbol else reference.ref.written_name
    return build_finding(
        rule_id=RULE_ID,
        rule_version=RULE_VERSION,
        module_id=reference.module_id,
        enclosing_symbol=reference.enclosing_symbol,
        subject=reference.id,
        normalized_subject=f"{role}:{symbol}:{reference.id.value}",
        message_key="security.direct_access",
        arguments=(("role", role), ("call", symbol)),
        location=reference.location,
        evidence=(EvidenceItem("effects", (effect.value,)),),
    )


def security_rule_definition() -> RuleDefinition:
    return RuleDefinition(
        id=RULE_ID,
        behavior_version=RULE_VERSION,
        title="보안 값 접근 위치 제한",
        help="환경 값·비밀 값·토큰 처리는 설정 또는 보안 역할의 승인된 함수에 두세요.",
        target=RuleTarget.MODULE,
        requirements=RuleRequirements(frozenset(), AnalysisStage.RESOLVED, False, False),
        change_impact=ChangeImpact.SELF,
        implementation=DirectSecurityAccessRule(),
        compliant_fixtures=("tests/fixtures/rules/security/compliant.py",),
        violation_fixtures=("tests/fixtures/rules/security/violation.py",),
        applies_to_zones=_ALL_ZONES,
    )
