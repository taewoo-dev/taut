from __future__ import annotations

from taut.analysis.semantic_model import SnapshotSemanticModel
from taut.domain.ids import ModuleId, RuleId
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition
from taut.policy.rules.async_safety import BlockingCallInAsyncRule
from taut.policy.rules.time_access import TimeAccessRule


def supports_effect_reuse(definition: RuleDefinition) -> bool:
    return (
        definition.id == RuleId("ASYNC001")
        and type(definition.implementation) is BlockingCallInAsyncRule
    ) or (definition.id == RuleId("TIME001") and type(definition.implementation) is TimeAccessRule)


def equivalent_effect_modules(
    context: PolicyContext,
    prior: PolicyContext,
    candidates: frozenset[ModuleId],
) -> frozenset[ModuleId]:
    """A conservative equality certificate for two audited built-in consumers.

    Raw calls, enclosing functions and target completeness must remain identical.
    Shared reads include canonical names, database effects, transitive summaries
    and callback invocation/binding facts. Catalog/policy equality is checked by
    PolicyEngine before this certificate is requested. Unknown models opt out.
    """
    if (
        type(context.model) is not SnapshotSemanticModel
        or type(prior.model) is not SnapshotSemanticModel
    ):
        return frozenset()
    if context.model.canonical_symbols != prior.model.canonical_symbols:
        return frozenset()
    if context.database_operations != prior.database_operations:
        return frozenset()
    if (
        context.function_summaries != prior.function_summaries
        or context.callback_index != prior.callback_index
    ):
        return frozenset()
    old_modules: frozenset[ModuleId] = frozenset(prior.model.modules())
    return frozenset(
        module
        for module in candidates
        if module in old_modules and context.model.module(module) is prior.model.module(module)
    )
