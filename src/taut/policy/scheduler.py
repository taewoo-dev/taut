from __future__ import annotations

from taut.configuration.catalog import EffectResolutionState
from taut.domain.evaluations import RuleTarget, RuleTargetRef
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition


class RuleScheduler:
    def targets_for(
        self,
        definition: RuleDefinition,
        context: PolicyContext,
    ) -> tuple[RuleTargetRef, ...]:
        target_kind = definition.target
        if target_kind is RuleTarget.PROJECT:
            return (RuleTargetRef(RuleTarget.PROJECT),)
        targets: list[RuleTargetRef] = []
        for module_id in context.model.modules():
            module = context.model.module(module_id)
            if not module.module.is_policy_target:
                continue
            if context.classification.get(module_id).zone not in definition.applies_to_zones:
                continue
            if target_kind is RuleTarget.MODULE:
                targets.append(RuleTargetRef(RuleTarget.MODULE, module_id=module_id))
            elif target_kind is RuleTarget.SYMBOL:
                targets.extend(
                    RuleTargetRef(
                        RuleTarget.SYMBOL,
                        module_id=module_id,
                        symbol_id=function.symbol_id,
                    )
                    for function in module.functions
                )
                targets.extend(
                    RuleTargetRef(
                        RuleTarget.SYMBOL,
                        module_id=module_id,
                        symbol_id=class_fact.symbol_id,
                    )
                    for class_fact in module.classes
                )
            elif target_kind in (RuleTarget.CALL, RuleTarget.OPERATION):
                for call in module.calls:
                    if target_kind is RuleTarget.OPERATION:
                        resolution = context.effect_of(call)
                        if resolution.state is not EffectResolutionState.MATCHED:
                            continue
                    targets.append(RuleTargetRef(target_kind, module_id=module_id, fact_id=call.id))
        return tuple(sorted(targets))
