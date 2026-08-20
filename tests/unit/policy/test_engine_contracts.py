from __future__ import annotations

from dataclasses import dataclass, replace

import pytest
from tests.utils.builders import analyze, make_context, make_source

from taut.analysis.providers import apply_fact_providers
from taut.configuration.catalog import EffectCatalog, EffectResolution, EffectResolver
from taut.configuration.manifest import Zone
from taut.domain.evaluations import (
    ChangeImpact,
    EvaluationReason,
    RuleLevel,
    RuleSetting,
    RuleTarget,
    RuleTargetRef,
    RuleVerdict,
)
from taut.domain.facts import AnalysisStage, CallFact
from taut.domain.frozen import FrozenMap
from taut.domain.ids import RuleId
from taut.policy.context import PolicyContext
from taut.policy.engine import PolicyEngine
from taut.policy.packs import SYNTAX_CAPABILITY, PythonCoreProvider
from taut.policy.registry import RuleRegistry
from taut.policy.rule import (
    Rule,
    RuleDefinition,
    RuleEvaluation,
    RuleRequirements,
)
from taut.policy.scheduler import RuleScheduler

_SYNTHETIC_RULE_ID = RuleId("ENGINE999")
_SECOND_SYNTHETIC_RULE_ID = RuleId("ENGINE998")


@dataclass(frozen=True)
class PassingRule:
    rule_id: RuleId = _SYNTHETIC_RULE_ID

    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        del context
        return RuleEvaluation(self.rule_id, target, RuleVerdict.PASS, ())


class ExplodingRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        del target, context
        raise RuntimeError("boom")


@dataclass(frozen=True)
class PassingWithGapRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        del context
        return RuleEvaluation(
            _SYNTHETIC_RULE_ID,
            target,
            RuleVerdict.PASS,
            (),
            coverage_gaps=(
                EvaluationReason("partial_relation", "일부 관계를 해석하지 못했습니다."),
            ),
        )


class CountingScheduler(RuleScheduler):
    def __init__(self) -> None:
        self.calls = 0

    def targets_for(
        self,
        definition: RuleDefinition,
        context: PolicyContext,
    ) -> tuple[RuleTargetRef, ...]:
        self.calls += 1
        return super().targets_for(definition, context)


class CountingEffectResolver(EffectResolver):
    def __init__(self) -> None:
        self.calls = 0

    def resolve(self, call: CallFact, catalog: EffectCatalog) -> EffectResolution:
        self.calls += 1
        return super().resolve(call, catalog)


def _definition(
    rule: Rule,
    *,
    rule_id: RuleId = _SYNTHETIC_RULE_ID,
    capabilities: frozenset[str] = frozenset(),
) -> RuleDefinition:
    return RuleDefinition(
        rule_id,
        1,
        "test rule",
        "help",
        RuleTarget.MODULE,
        RuleRequirements(capabilities, AnalysisStage.FACTS_READY, False, False),
        ChangeImpact.SELF,
        rule,
        ("compliant",),
        ("violation",),
    )


def _context() -> PolicyContext:
    snapshot = analyze(make_source("app/a.py", "value = 1"))
    context = make_context(
        snapshot,
        roles={"service": ("app/**",)},
        levels={
            "TIME001": RuleLevel.OFF,
            "TX001": RuleLevel.OFF,
            "ARCH001": RuleLevel.OFF,
            "ARCH002": RuleLevel.OFF,
        },
    )
    return _enable_test_rule(context)


def _enable_test_rule(context: PolicyContext) -> PolicyContext:
    return _enable_rules(context, _SYNTHETIC_RULE_ID)


def _enable_rules(context: PolicyContext, *rule_ids: RuleId) -> PolicyContext:
    policy = replace(
        context.policy,
        rules=FrozenMap(
            (
                *context.policy.rules.items(),
                *((rule_id, RuleSetting(RuleLevel.ENFORCED, FrozenMap())) for rule_id in rule_ids),
            )
        ),
    )
    return PolicyContext(
        context.model,
        context.classification,
        context.effects,
        context.catalog,
        policy,
    )


def test_registry_rejects_duplicate_rule_ids() -> None:
    definition = _definition(PassingRule())

    with pytest.raises(ValueError, match="duplicate"):
        RuleRegistry.build((definition, definition))


def test_rule_exception_is_isolated_and_indeterminate() -> None:
    result = PolicyEngine(RuleRegistry.build((_definition(ExplodingRule()),))).run(_context())

    assert result.evaluations[0].verdict is RuleVerdict.INDETERMINATE
    assert result.engine_issues[0].code == "RULE_FAILURE"


def test_missing_capability_skips_rule_execution() -> None:
    result = PolicyEngine(
        RuleRegistry.build((_definition(PassingRule(), capabilities=frozenset({"types"})),))
    ).run(_context())

    assert result.evaluations[0].verdict is RuleVerdict.INDETERMINATE
    assert result.coverage.skipped[0].reason.code == "missing_capability"


def test_available_capability_allows_rule_execution() -> None:
    base = analyze(make_source("app/a.py", "value = 1"))
    context = _enable_test_rule(
        make_context(
            apply_fact_providers(base, (PythonCoreProvider(),)),
            roles={"service": ("app/**",)},
        )
    )
    definition = _definition(PassingRule(), capabilities=frozenset({SYNTAX_CAPABILITY}))

    result = PolicyEngine(RuleRegistry.build((definition,))).run(context)

    assert result.evaluations[0].verdict is RuleVerdict.PASS
    assert result.coverage.skipped == ()


def test_pass_can_report_a_coverage_gap_without_hiding_the_verdict() -> None:
    result = PolicyEngine(RuleRegistry.build((_definition(PassingWithGapRule()),))).run(_context())

    assert result.evaluations[0].verdict is RuleVerdict.PASS
    assert result.coverage.passed == 1
    assert result.coverage.gaps[0].reason.code == "partial_relation"


def test_symbol_scheduler_targets_functions_and_classes() -> None:
    snapshot = analyze(make_source("app/a.py", "class Item: ...\ndef run(): ..."))
    context = _enable_test_rule(
        make_context(
            snapshot,
            roles={"service": ("app/**",)},
        )
    )
    definition = replace(_definition(PassingRule()), target=RuleTarget.SYMBOL)

    result = PolicyEngine(RuleRegistry.build((definition,))).run(context)

    assert len(result.evaluations) == 2
    assert {
        item.target.symbol_id.value for item in result.evaluations if item.target.symbol_id
    } == {
        "app.a.Item",
        "app.a.run",
    }


def test_scheduler_skips_modules_outside_rule_zones() -> None:
    snapshot = analyze(make_source("app/a.py", "value = 1"))
    context = _enable_test_rule(
        make_context(
            snapshot,
            roles={"service": ("app/**",)},
            zones={"test": ("app/**",)},
        )
    )
    definition = replace(
        _definition(PassingRule()),
        applies_to_zones=frozenset({Zone("prod")}),
    )

    result = PolicyEngine(RuleRegistry.build((definition,))).run(context)

    assert result.evaluations == ()


def test_engine_reuses_targets_for_rules_with_the_same_target_shape() -> None:
    context = _enable_rules(_context(), _SECOND_SYNTHETIC_RULE_ID)
    scheduler = CountingScheduler()
    second = _definition(
        PassingRule(_SECOND_SYNTHETIC_RULE_ID),
        rule_id=_SECOND_SYNTHETIC_RULE_ID,
    )

    result = PolicyEngine(
        RuleRegistry.build((_definition(PassingRule()), second)),
        scheduler,
    ).run(context)

    assert scheduler.calls == 1
    assert len(result.evaluations) == 2


def test_context_resolves_each_call_effect_once() -> None:
    snapshot = analyze(make_source("app/a.py", "import time\ntime.time()"))
    context = make_context(snapshot, roles={"service": ("app/**",)})
    resolver = CountingEffectResolver()
    context = replace(context, effects=resolver)
    call = context.model.module(next(iter(context.model.modules()))).calls[0]

    first = context.effect_of(call)
    second = context.effect_of(call)

    assert first is second
    assert resolver.calls == 1
