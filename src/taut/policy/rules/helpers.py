from __future__ import annotations

from taut.configuration.catalog import Effect
from taut.domain.evaluations import EvaluationReason, RuleTargetRef, RuleVerdict
from taut.domain.facts import CompletenessState, ResolutionState
from taut.domain.findings import (
    EvidenceItem,
    Finding,
    FindingSubject,
    RelatedLocation,
    ScalarValue,
    make_fingerprint,
)
from taut.domain.frozen import FrozenMap
from taut.domain.ids import FactId, ModuleId, RuleId, SymbolId
from taut.domain.location import SourceRange
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleEvaluation


def incomplete_module_evaluation(
    rule_id: RuleId, target: RuleTargetRef, context: PolicyContext, module_id: ModuleId
) -> RuleEvaluation | None:
    module = context.model.module(module_id)
    if module.completeness.state is CompletenessState.COMPLETE:
        return None
    return RuleEvaluation(
        rule_id,
        target,
        RuleVerdict.INDETERMINATE,
        (),
        EvaluationReason("incomplete_module", "규칙에 필요한 모듈 사실이 완성되지 않았습니다."),
    )


def uncertain_provider_evaluation(
    rule_id: RuleId,
    target: RuleTargetRef,
    context: PolicyContext,
    capability_names: tuple[str, ...],
    module_id: ModuleId,
    require_capabilities: bool = False,
) -> RuleEvaluation | None:
    model = context.model
    for capability in capability_names:
        if require_capabilities and capability not in model.capabilities():
            return RuleEvaluation(
                rule_id,
                target,
                RuleVerdict.INDETERMINATE,
                (),
                EvaluationReason(
                    "missing_capability",
                    f"provider capability {capability} is unavailable.",
                ),
            )
        for fact in model.capability_values(capability):
            if getattr(fact, "module_id", None) != module_id:
                continue
            confidence = getattr(fact, "confidence", ResolutionState.RESOLVED)
            if confidence is not ResolutionState.RESOLVED:
                return RuleEvaluation(
                    rule_id,
                    target,
                    RuleVerdict.INDETERMINATE,
                    (),
                    EvaluationReason(
                        "uncertain_provider_fact",
                        "provider가 규칙에 필요한 사실을 확정하지 못했습니다.",
                    ),
                )
    return None


def rule_uncertainty(
    rule_id: RuleId,
    target: RuleTargetRef,
    context: PolicyContext,
    module_id: ModuleId,
    capabilities: tuple[str, ...] = (),
    require_capabilities: bool = False,
) -> RuleEvaluation | None:
    return incomplete_module_evaluation(rule_id, target, context, module_id) or (
        uncertain_provider_evaluation(
            rule_id, target, context, capabilities, module_id, require_capabilities
        )
        if capabilities
        else None
    )


def target_uncertainty(
    rule_id: RuleId,
    target: RuleTargetRef,
    context: PolicyContext,
    capabilities: tuple[str, ...] = (),
    require_capabilities: bool = False,
) -> RuleEvaluation | None:
    if target.module_id is None:
        return None
    return rule_uncertainty(
        rule_id, target, context, target.module_id, capabilities, require_capabilities
    )


def module_fact_uncertainty(
    rule_id: RuleId,
    target: RuleTargetRef,
    context: PolicyContext,
    module_id: ModuleId,
    *,
    imports: bool = True,
    calls: bool = True,
    references: bool = True,
) -> RuleEvaluation | None:
    """Propagate module completeness; edge checks use resolver-owned predicates."""
    incomplete = incomplete_module_evaluation(rule_id, target, context, module_id)
    if incomplete is not None:
        return incomplete
    return None


def project_fact_uncertainty(
    rule_id: RuleId, target: RuleTargetRef, context: PolicyContext
) -> RuleEvaluation | None:
    """Project graph rules remain deterministic only over a complete graph."""
    if any(
        context.model.module(module_id).completeness.state is not CompletenessState.COMPLETE
        for module_id in context.model.modules()
    ):
        return RuleEvaluation(
            rule_id,
            target,
            RuleVerdict.INDETERMINATE,
            (),
            EvaluationReason(
                "incomplete_project", "규칙에 필요한 project graph가 완성되지 않았습니다."
            ),
        )
    return None


def unresolved_call_evaluation(
    rule_id: RuleId,
    target: RuleTargetRef,
    context: PolicyContext,
    module_id: ModuleId,
    candidates: tuple[SymbolId, ...],
) -> RuleEvaluation | None:
    """Return indeterminate when a module call may be a relevant symbol."""
    names = frozenset(candidates)
    for call in context.model.calls_in(module_id):
        if call.ref.state is ResolutionState.RESOLVED:
            continue
        if call.ref.symbol in names or names.intersection(call.ref.candidates):
            return RuleEvaluation(
                rule_id,
                target,
                RuleVerdict.INDETERMINATE,
                (),
                EvaluationReason(
                    "uncertain_symbol", "규칙에 필요한 call symbol을 확정하지 못했습니다."
                ),
            )
    return None


def unresolved_target_call_evaluation(
    rule_id: RuleId,
    target: RuleTargetRef,
    context: PolicyContext,
    call_id: FactId,
    candidates: tuple[SymbolId, ...],
) -> RuleEvaluation | None:
    """Return indeterminate only when the current call target may be relevant."""
    call = context.model.call(call_id)
    if call.ref.state is ResolutionState.RESOLVED:
        return None
    names = frozenset(candidates)
    if call.ref.symbol in names or names.intersection(call.ref.candidates):
        return RuleEvaluation(
            rule_id,
            target,
            RuleVerdict.INDETERMINATE,
            (),
            EvaluationReason(
                "uncertain_symbol", "규칙에 필요한 call symbol을 확정하지 못했습니다."
            ),
        )
    return None


def unresolved_effect_evaluation(
    rule_id: RuleId,
    target: RuleTargetRef,
    context: PolicyContext,
    call_id: FactId,
    effects: frozenset[Effect],
) -> RuleEvaluation | None:
    """Propagate uncertainty only from resolver-owned effect candidates.

    Written call text is deliberately not consulted: unresolved and dynamic
    references have no semantic identity unless the resolver preserved a
    candidate set that intersects the configured catalog effect.
    """
    call = context.model.call(call_id)
    if call.ref.state is ResolutionState.RESOLVED:
        return None
    relevant = {
        entry.symbol
        for entry in context.catalog.entries.values()
        if entry.effects.intersection(effects)
    }
    if relevant.intersection(call.ref.candidates):
        return RuleEvaluation(
            rule_id,
            target,
            RuleVerdict.INDETERMINATE,
            (),
            EvaluationReason(
                "uncertain_effect", "규칙에 필요한 effect 대상을 확정하지 못했습니다."
            ),
        )
    return None


def unresolved_use_evaluation(
    rule_id: RuleId,
    target: RuleTargetRef,
    context: PolicyContext,
    module_id: ModuleId,
    candidates: tuple[SymbolId, ...],
) -> RuleEvaluation | None:
    """Propagate uncertain use edges only when resolver candidates are relevant."""
    names = frozenset(candidates)
    for edge in context.model.uses(module_id):
        if edge.ref.state is ResolutionState.RESOLVED:
            continue
        if edge.ref.symbol in names or names.intersection(edge.ref.candidates):
            return RuleEvaluation(
                rule_id,
                target,
                RuleVerdict.INDETERMINATE,
                (),
                EvaluationReason(
                    "uncertain_symbol", "규칙에 필요한 use symbol을 확정하지 못했습니다."
                ),
            )
    return None


def unresolved_import_evaluation(
    rule_id: RuleId,
    target: RuleTargetRef,
    context: PolicyContext,
    module_id: ModuleId,
    prefixes: tuple[ModuleId, ...],
) -> RuleEvaluation | None:
    """Propagate only unresolved imports participating in configured boundaries."""
    for item in context.model.unresolved_imports():
        if item.importer != module_id:
            continue
        if any(
            fact.imported_module_name == item.written_name
            for fact in context.model.module(module_id).imports
        ):
            # The import syntax itself is sufficient for prefix-based policies.
            continue
        if any(
            item.written_name == prefix.value or item.written_name.startswith(f"{prefix.value}.")
            for prefix in prefixes
        ):
            return RuleEvaluation(
                rule_id,
                target,
                RuleVerdict.INDETERMINATE,
                (),
                EvaluationReason(
                    "uncertain_import", "규칙에 필요한 import edge를 확정하지 못했습니다."
                ),
            )
    return None


def build_policy_finding(
    rule_id: RuleId,
    module_id: ModuleId,
    enclosing_symbol: SymbolId,
    subject: FindingSubject,
    location: SourceRange,
    message_key: str,
    kind: str,
    rule_version: int = 1,
) -> Finding:
    return build_finding(
        rule_id=rule_id,
        rule_version=rule_version,
        module_id=module_id,
        enclosing_symbol=enclosing_symbol,
        subject=subject,
        normalized_subject=f"{kind}:{subject.value}",
        message_key=message_key,
        arguments=(("symbol", enclosing_symbol.value), ("missing", kind)),
        location=location,
        evidence=(EvidenceItem("symbol", enclosing_symbol.value), EvidenceItem("missing", kind)),
    )


def build_finding(
    *,
    rule_id: RuleId,
    rule_version: int,
    module_id: ModuleId,
    enclosing_symbol: SymbolId | None,
    subject: FindingSubject,
    normalized_subject: str,
    message_key: str,
    arguments: tuple[tuple[str, ScalarValue], ...],
    location: SourceRange,
    evidence: tuple[EvidenceItem, ...],
    related_locations: tuple[RelatedLocation, ...] = (),
) -> Finding:
    evidence_key = "|".join(f"{item.key}={item.value}" for item in evidence)
    return Finding(
        rule_id=rule_id,
        rule_version=rule_version,
        module_id=module_id,
        enclosing_symbol=enclosing_symbol,
        subject=subject,
        message_key=message_key,
        arguments=FrozenMap(arguments),
        primary_location=location,
        related_locations=related_locations,
        evidence=evidence,
        fingerprint=make_fingerprint(
            rule_id=rule_id,
            rule_version=rule_version,
            module_id=module_id,
            enclosing_symbol=enclosing_symbol,
            normalized_subject=normalized_subject,
            evidence_key=evidence_key,
        ),
    )
