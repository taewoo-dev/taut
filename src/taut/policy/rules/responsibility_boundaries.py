from __future__ import annotations

from dataclasses import dataclass

from taut.domain.evaluations import ChangeImpact, RuleTarget, RuleTargetRef, RuleVerdict
from taut.domain.facts import AnalysisStage, CallFact, GuardKind, ImportFact, ResolutionState
from taut.domain.findings import EvidenceItem, Finding
from taut.domain.ids import ModuleId, RuleId, SymbolId
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import (
    build_finding,
    module_fact_uncertainty,
    unresolved_call_evaluation,
    unresolved_import_evaluation,
)

SERVICE_RULE_ID = RuleId("BOUNDARY002")
CONTRACT_RULE_ID = RuleId("BOUNDARY003")
ADAPTER_RULE_ID = RuleId("ADAPTER001")
RULE_VERSION = 1


def _matches_module(import_fact: ImportFact, prefix: ModuleId) -> bool:
    imported = import_fact.imported_module_name
    return imported == prefix.value or imported.startswith(f"{prefix.value}.")


def _matches_symbol(call: CallFact, prefix: SymbolId, context: PolicyContext) -> bool:
    symbol = call.ref.symbol
    return bool(
        call.ref.state is ResolutionState.RESOLVED
        and symbol is not None
        and context.matching_symbol(symbol, (prefix,)) is not None
    )


@dataclass(frozen=True)
class _ImportBoundaryRule:
    rule_id: RuleId
    role_set_name: str
    prefix_set_name: str
    message_key: str

    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError(f"{self.rule_id.value} requires a module target")
        classification = context.classification.get(target.module_id)
        roles = getattr(context.policy.boundaries, self.role_set_name)
        role = classification.role
        if role is None or role not in roles:
            return RuleEvaluation(self.rule_id, target, RuleVerdict.NOT_APPLICABLE, ())
        uncertainty = module_fact_uncertainty(self.rule_id, target, context, target.module_id)
        if uncertainty is not None:
            return uncertainty
        prefixes = getattr(context.policy.boundaries, self.prefix_set_name)
        uncertainty = unresolved_import_evaluation(
            self.rule_id, target, context, target.module_id, prefixes
        )
        if uncertainty is not None:
            return uncertainty
        findings: list[Finding] = []
        seen: set[tuple[str, int, int]] = set()
        for import_fact in context.model.module(target.module_id).imports:
            if import_fact.context.guard is GuardKind.TYPE_CHECKING_ONLY:
                continue
            prefix = next(
                (item for item in prefixes if _matches_module(import_fact, item)),
                None,
            )
            if prefix is None:
                continue
            key = (
                prefix.value,
                import_fact.location.start_line,
                import_fact.location.start_column,
            )
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                _import_finding(
                    self.rule_id,
                    self.message_key,
                    import_fact,
                    prefix,
                    role.value,
                )
            )
        if findings:
            return RuleEvaluation(self.rule_id, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(self.rule_id, target, RuleVerdict.PASS, ())


def _import_finding(
    rule_id: RuleId,
    message_key: str,
    import_fact: ImportFact,
    prefix: ModuleId,
    role: str,
) -> Finding:
    return build_finding(
        rule_id=rule_id,
        rule_version=RULE_VERSION,
        module_id=import_fact.module_id,
        enclosing_symbol=import_fact.enclosing_symbol,
        subject=import_fact.id,
        normalized_subject=f"{role}:{prefix.value}:{import_fact.id.value}",
        message_key=message_key,
        arguments=(("role", role), ("imported", import_fact.imported_module_name)),
        location=import_fact.location,
        evidence=(
            EvidenceItem("role", role),
            EvidenceItem("imported", import_fact.imported_module_name),
            EvidenceItem("forbidden_prefix", prefix.value),
        ),
    )


class AdapterBoundaryRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("ADAPTER001 requires a module target")
        classification = context.classification.get(target.module_id)
        boundaries = context.policy.boundaries
        role = classification.role
        if role is None or role not in boundaries.adapter_roles:
            return RuleEvaluation(ADAPTER_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        uncertainty = module_fact_uncertainty(ADAPTER_RULE_ID, target, context, target.module_id)
        if uncertainty is not None:
            return uncertainty
        uncertainty = unresolved_import_evaluation(
            ADAPTER_RULE_ID,
            target,
            context,
            target.module_id,
            boundaries.adapter_forbidden_modules,
        )
        if uncertainty is not None:
            return uncertainty
        uncertainty = unresolved_call_evaluation(
            ADAPTER_RULE_ID,
            target,
            context,
            target.module_id,
            boundaries.adapter_forbidden_calls,
        )
        if uncertainty is not None:
            return uncertainty
        module = context.model.module(target.module_id)
        findings: list[Finding] = []
        seen_imports: set[tuple[str, int, int]] = set()
        for import_fact in module.imports:
            if import_fact.context.guard is GuardKind.TYPE_CHECKING_ONLY:
                continue
            import_prefix = next(
                (
                    item
                    for item in boundaries.adapter_forbidden_modules
                    if _matches_module(import_fact, item)
                ),
                None,
            )
            if import_prefix is not None:
                key = (
                    import_prefix.value,
                    import_fact.location.start_line,
                    import_fact.location.start_column,
                )
                if key in seen_imports:
                    continue
                seen_imports.add(key)
                findings.append(
                    _import_finding(
                        ADAPTER_RULE_ID,
                        "adapter.database_import",
                        import_fact,
                        import_prefix,
                        role.value,
                    )
                )
        for call in module.calls:
            call_prefix = next(
                (
                    item
                    for item in boundaries.adapter_forbidden_calls
                    if _matches_symbol(call, item, context)
                ),
                None,
            )
            if call_prefix is None:
                continue
            findings.append(
                build_finding(
                    rule_id=ADAPTER_RULE_ID,
                    rule_version=RULE_VERSION,
                    module_id=call.module_id,
                    enclosing_symbol=call.enclosing_symbol,
                    subject=call.id,
                    normalized_subject=f"call:{call_prefix.value}:{call.id.value}",
                    message_key="adapter.database_call",
                    arguments=(("call", call.ref.written_name),),
                    location=call.location,
                    evidence=(
                        EvidenceItem("call", call.ref.written_name),
                        EvidenceItem("forbidden_prefix", call_prefix.value),
                    ),
                )
            )
        if findings:
            return RuleEvaluation(ADAPTER_RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(ADAPTER_RULE_ID, target, RuleVerdict.PASS, ())


def responsibility_boundary_rule_definitions() -> tuple[
    RuleDefinition, RuleDefinition, RuleDefinition
]:
    requirements = RuleRequirements(frozenset(), AnalysisStage.FACTS_READY, False, False)
    service = RuleDefinition(
        id=SERVICE_RULE_ID,
        behavior_version=RULE_VERSION,
        title="Service 외부 SDK 직접 사용 금지",
        help="Service는 외부 SDK 대신 내부 Contract를 사용하세요.",
        target=RuleTarget.MODULE,
        requirements=requirements,
        change_impact=ChangeImpact.SELF,
        implementation=_ImportBoundaryRule(
            SERVICE_RULE_ID,
            "service_roles",
            "external_modules",
            "service.external_import",
        ),
        compliant_fixtures=("tests/fixtures/rules/responsibility_boundary/service_compliant.py",),
        violation_fixtures=("tests/fixtures/rules/responsibility_boundary/service_violation.py",),
    )
    contract = RuleDefinition(
        id=CONTRACT_RULE_ID,
        behavior_version=RULE_VERSION,
        title="Contract 외부 구현 의존 금지",
        help="Contract에는 외부 프레임워크와 SDK 자료형을 노출하지 마세요.",
        target=RuleTarget.MODULE,
        requirements=requirements,
        change_impact=ChangeImpact.SELF,
        implementation=_ImportBoundaryRule(
            CONTRACT_RULE_ID,
            "contract_roles",
            "contract_forbidden_modules",
            "contract.external_import",
        ),
        compliant_fixtures=("tests/fixtures/rules/responsibility_boundary/contract_compliant.py",),
        violation_fixtures=("tests/fixtures/rules/responsibility_boundary/contract_violation.py",),
    )
    adapter = RuleDefinition(
        id=ADAPTER_RULE_ID,
        behavior_version=RULE_VERSION,
        title="Adapter DB 접근 금지",
        help="Adapter는 외부 연결만 맡고 DB와 transaction은 Service에 두세요.",
        target=RuleTarget.MODULE,
        requirements=requirements,
        change_impact=ChangeImpact.SELF,
        implementation=AdapterBoundaryRule(),
        compliant_fixtures=("tests/fixtures/rules/responsibility_boundary/adapter_compliant.py",),
        violation_fixtures=("tests/fixtures/rules/responsibility_boundary/adapter_violation.py",),
    )
    return service, contract, adapter
