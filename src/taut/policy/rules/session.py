from __future__ import annotations

from taut.configuration.effective_policy import PolicyApproval
from taut.domain.evaluations import (
    ChangeImpact,
    EvaluationReason,
    RuleTarget,
    RuleTargetRef,
    RuleVerdict,
)
from taut.domain.facts import AnalysisStage, ExpressionSummary, FunctionFact, ResolutionState
from taut.domain.findings import EvidenceItem, Finding
from taut.domain.ids import ModuleId, RuleId, SymbolId
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import (
    build_finding,
    target_uncertainty,
    unresolved_target_call_evaluation,
)

OWNER_RULE_ID = RuleId("SESSION001")
NESTED_RULE_ID = RuleId("SESSION002")
PARAMETER_RULE_ID = RuleId("SESSION003")
RULE_VERSION = 2
PARAMETER_RULE_VERSION = 2
_TRANSACTION_CONTROL_METHODS = frozenset({"begin", "begin_nested", "commit", "rollback"})


class SessionOwnerRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.fact_id is None or target.module_id is None:
            raise ValueError("SESSION001 requires a call target")
        incomplete = target_uncertainty(OWNER_RULE_ID, target, context)
        if incomplete is not None:
            return incomplete
        call = context.model.call(target.fact_id)
        if call.ref.state is not ResolutionState.RESOLVED:
            uncertain = unresolved_target_call_evaluation(
                OWNER_RULE_ID,
                target,
                context,
                call.id,
                tuple(context.policy.transaction_session_providers),
            )
            if uncertain is not None:
                return uncertain
            return RuleEvaluation(OWNER_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        if call.ref.state is not ResolutionState.RESOLVED or call.ref.symbol is None:
            return RuleEvaluation(OWNER_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        if not context.symbol_in(call.ref.symbol, context.policy.transaction_session_providers):
            return RuleEvaluation(OWNER_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        if context.symbol_in(call.enclosing_symbol, context.policy.transaction_session_providers):
            return RuleEvaluation(OWNER_RULE_ID, target, RuleVerdict.PASS, ())
        classification = context.classification.get(target.module_id)
        if classification.role is None:
            return RuleEvaluation(
                OWNER_RULE_ID,
                target,
                RuleVerdict.INDETERMINATE,
                (),
                EvaluationReason("missing_role", "No role is assigned to this file."),
            )
        if classification.role in context.policy.transaction_owner_roles:
            return RuleEvaluation(OWNER_RULE_ID, target, RuleVerdict.PASS, ())
        provider = call.ref.symbol.value
        finding = build_finding(
            rule_id=OWNER_RULE_ID,
            rule_version=RULE_VERSION,
            module_id=call.module_id,
            enclosing_symbol=call.enclosing_symbol,
            subject=call.id,
            normalized_subject=f"{provider}:{classification.role.value}:{call.id.value}",
            message_key="session.outside_owner",
            arguments=(("provider", provider), ("role", classification.role.value)),
            location=call.location,
            evidence=(
                EvidenceItem("provider", provider),
                EvidenceItem("role", classification.role.value),
            ),
        )
        return RuleEvaluation(OWNER_RULE_ID, target, RuleVerdict.FAIL, (finding,))


class NestedSessionRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.fact_id is None:
            raise ValueError("SESSION002 requires a call target")
        incomplete = target_uncertainty(NESTED_RULE_ID, target, context)
        if incomplete is not None:
            return incomplete
        call = context.model.call(target.fact_id)
        if call.ref.state is not ResolutionState.RESOLVED:
            uncertain = unresolved_target_call_evaluation(
                NESTED_RULE_ID,
                target,
                context,
                call.id,
                tuple(context.policy.transaction_session_providers),
            )
            if uncertain is not None:
                return uncertain
            return RuleEvaluation(NESTED_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        provider = call.ref.symbol
        direct_provider = provider is not None and context.symbol_in(
            provider, context.policy.transaction_session_providers
        )
        summary = context.function_summary(provider)
        inferred_providers: frozenset[SymbolId] = (
            summary.session_providers if summary is not None else frozenset()
        )
        if not direct_provider and not inferred_providers:
            return RuleEvaluation(NESTED_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        enclosing = next(
            (
                item.symbol
                for item in call.enclosing_contexts
                if context.symbol_in(item.symbol, context.policy.transaction_session_providers)
            ),
            None,
        )
        if enclosing is None:
            return RuleEvaluation(NESTED_RULE_ID, target, RuleVerdict.PASS, ())
        reported_provider = (
            provider if direct_provider and provider is not None else sorted(inferred_providers)[0]
        )
        finding = build_finding(
            rule_id=NESTED_RULE_ID,
            rule_version=RULE_VERSION,
            module_id=call.module_id,
            enclosing_symbol=call.enclosing_symbol,
            subject=call.id,
            normalized_subject=f"{enclosing.value}:{reported_provider.value}:{call.id.value}",
            message_key="session.nested",
            arguments=(("provider", reported_provider.value),),
            location=call.location,
            evidence=(
                EvidenceItem("outer_provider", enclosing.value),
                EvidenceItem("inner_provider", reported_provider.value),
            ),
        )
        return RuleEvaluation(NESTED_RULE_ID, target, RuleVerdict.FAIL, (finding,))


def _session_annotation(
    annotation: ExpressionSummary | None,
    session_types: tuple[SymbolId, ...],
    context: PolicyContext,
) -> SymbolId | None:
    if annotation is None:
        return None
    configured = frozenset(session_types)
    return next(
        (
            symbol
            for symbol in annotation.symbols
            if context.symbol_in_or_inherits(symbol, configured)
        ),
        None,
    )


class ServiceSessionParameterRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("SESSION003 requires a module target")
        incomplete = target_uncertainty(PARAMETER_RULE_ID, target, context)
        if incomplete is not None:
            return incomplete
        role = context.classification.get(target.module_id).role
        if role is None or role not in context.policy.boundaries.service_roles:
            return RuleEvaluation(PARAMETER_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        findings: list[Finding] = []
        approval_keys: set[str] = set()
        for function in context.model.module(target.module_id).functions:
            session_type = next(
                (
                    symbol
                    for parameter in function.parameters
                    if (
                        symbol := _session_annotation(
                            parameter.annotation,
                            context.policy.boundaries.session_type_symbols,
                            context,
                        )
                    )
                    is not None
                ),
                None,
            )
            if session_type is None:
                continue
            approval = _session_parameter_approval(
                function, session_type, target.module_id, context
            )
            mode = (
                approval.kind
                if approval is not None
                else "participant"
                if role in context.policy.transaction_participant_roles
                else None
            )
            if approval is not None:
                approval_keys.add(approval.key)
            if mode == "managed":
                continue
            if mode == "participant" or _private_local_helper(function, target.module_id, context):
                unsafe = _participant_transaction_control(
                    function, session_type, target.module_id, context
                )
                if unsafe is None:
                    continue
                findings.append(
                    build_finding(
                        rule_id=PARAMETER_RULE_ID,
                        rule_version=PARAMETER_RULE_VERSION,
                        module_id=target.module_id,
                        enclosing_symbol=function.symbol_id,
                        subject=function.id,
                        normalized_subject=f"{function.symbol_id.value}:unsafe:{unsafe}",
                        message_key="session.participant_owns_transaction",
                        arguments=(
                            ("symbol", function.symbol_id.value),
                            ("operation", unsafe),
                        ),
                        location=function.location,
                        evidence=(
                            EvidenceItem("session_type", session_type.value),
                            EvidenceItem("operation", unsafe),
                        ),
                    )
                )
                continue
            findings.append(
                build_finding(
                    rule_id=PARAMETER_RULE_ID,
                    rule_version=PARAMETER_RULE_VERSION,
                    module_id=target.module_id,
                    enclosing_symbol=function.symbol_id,
                    subject=function.id,
                    normalized_subject=f"{function.symbol_id.value}:{session_type.value}",
                    message_key="session.service_parameter",
                    arguments=(("symbol", function.symbol_id.value),),
                    location=function.location,
                    evidence=(EvidenceItem("session_type", session_type.value),),
                )
            )
        verdict = RuleVerdict.FAIL if findings else RuleVerdict.PASS
        return RuleEvaluation(
            PARAMETER_RULE_ID,
            target,
            verdict,
            tuple(findings),
            approval_keys=tuple(sorted(approval_keys)),
        )


def _session_parameter_approval(
    function: FunctionFact,
    session_type: SymbolId,
    module_id: ModuleId,
    context: PolicyContext,
) -> PolicyApproval | None:
    subjects = (function.symbol_id, *(item.symbol for item in function.decorators if item.symbol))
    for mode in ("participant", "managed"):
        for subject in subjects:
            approval = context.approval_for(
                PARAMETER_RULE_ID,
                subject,
                module_id,
                target=session_type.value,
                kind=mode,
            )
            if approval is not None:
                return approval
    return None


def _private_local_helper(
    function: FunctionFact,
    module_id: ModuleId,
    context: PolicyContext,
) -> bool:
    if not function.name.startswith("_"):
        return False
    callers = tuple(
        call
        for candidate_module in context.model.modules()
        for call in context.model.calls_in(candidate_module)
        if call.ref.state is ResolutionState.RESOLVED and call.ref.symbol == function.symbol_id
    )
    return all(call.module_id == module_id for call in callers)


def _participant_transaction_control(
    function: FunctionFact,
    session_type: SymbolId,
    module_id: ModuleId,
    context: PolicyContext,
) -> str | None:
    for call in context.model.calls_in(module_id):
        if call.enclosing_symbol != function.symbol_id or call.ref.symbol is None:
            continue
        if context.symbol_in(call.ref.symbol, context.policy.transaction_session_providers):
            return call.ref.symbol.value
        owner, _, method = call.ref.symbol.value.rpartition(".")
        if owner == session_type.value and method in _TRANSACTION_CONTROL_METHODS:
            return call.ref.symbol.value
    return None


def session_rule_definitions() -> tuple[RuleDefinition, ...]:
    call_requirements = RuleRequirements(frozenset(), AnalysisStage.RESOLVED, False, False)
    module_requirements = RuleRequirements(frozenset(), AnalysisStage.FACTS_READY, False, False)
    return (
        RuleDefinition(
            id=OWNER_RULE_ID,
            behavior_version=RULE_VERSION,
            title="DB session ownership",
            help="Open DB sessions only within configured transaction owners.",
            target=RuleTarget.CALL,
            requirements=call_requirements,
            change_impact=ChangeImpact.SELF,
            implementation=SessionOwnerRule(),
            compliant_fixtures=("tests/fixtures/rules/session/compliant.py",),
            violation_fixtures=("tests/fixtures/rules/session/violation.py",),
        ),
        RuleDefinition(
            id=NESTED_RULE_ID,
            behavior_version=RULE_VERSION,
            title="No nested DB sessions",
            help="Do not open another session inside a session context.",
            target=RuleTarget.CALL,
            requirements=call_requirements,
            change_impact=ChangeImpact.SELF,
            implementation=NestedSessionRule(),
            compliant_fixtures=("tests/fixtures/rules/session_nested/compliant.py",),
            violation_fixtures=("tests/fixtures/rules/session_nested/violation.py",),
        ),
        RuleDefinition(
            id=PARAMETER_RULE_ID,
            behavior_version=PARAMETER_RULE_VERSION,
            title="Service transaction participation contract",
            help=(
                "Standalone Services own transactions. Mark participants with "
                "approved symbols or decorators, "
                "and do not open new sessions or commit/rollback in participants."
            ),
            target=RuleTarget.MODULE,
            requirements=module_requirements,
            change_impact=ChangeImpact.SELF,
            implementation=ServiceSessionParameterRule(),
            compliant_fixtures=("tests/fixtures/rules/session_parameter/compliant.py",),
            violation_fixtures=("tests/fixtures/rules/session_parameter/violation.py",),
        ),
    )
