from __future__ import annotations

from dataclasses import dataclass, replace

from tests.utils.builders import analyze, make_context, make_source

from taut.analysis.semantic_model import SnapshotSemanticModel
from taut.domain.evaluations import (
    ChangeImpact,
    RuleLevel,
    RuleSetting,
    RuleTarget,
    RuleTargetRef,
    RuleVerdict,
)
from taut.domain.facts import AnalysisStage
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, RuleId
from taut.incremental import ChangeSet, ImpactGraph
from taut.policy.context import PolicyContext
from taut.policy.engine import PolicyEngine
from taut.policy.registry import RuleRegistry
from taut.policy.rule import Rule, RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules import builtin_rule_registry

_RULE = RuleId("INCR001")


@dataclass
class CountingRule:
    rule_id: RuleId = _RULE

    def __post_init__(self) -> None:
        self.calls: list[RuleTargetRef] = []

    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        del context
        self.calls.append(target)
        return RuleEvaluation(self.rule_id, target, RuleVerdict.PASS, ())


class ExplodingRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        del target, context
        raise RuntimeError("boom")


def _definition(
    implementation: Rule,
    *,
    impact: ChangeImpact = ChangeImpact.SELF,
    target: RuleTarget = RuleTarget.MODULE,
    behavior_version: int = 1,
) -> RuleDefinition:
    return RuleDefinition(
        _RULE,
        behavior_version,
        "incremental test",
        "help",
        target,
        RuleRequirements(frozenset(), AnalysisStage.FACTS_READY, False, False),
        impact,
        implementation,
        ("compliant",),
        ("violation",),
    )


def _context(
    *sources: tuple[str, str], zones: dict[str, tuple[str, ...]] | None = None
) -> PolicyContext:
    base = make_context(
        analyze(*(make_source(path, content) for path, content in sources)),
        roles={"service": ("app/**",)},
        zones=zones,
    )
    policy = replace(
        base.policy,
        rules=FrozenMap(
            (
                *base.policy.rules.items(),
                (_RULE, RuleSetting(RuleLevel.ENFORCED, FrozenMap())),
            )
        ),
    )
    return replace(base, policy=policy)


def _engine(
    rule: Rule,
    *,
    impact: ChangeImpact = ChangeImpact.SELF,
    target: RuleTarget = RuleTarget.MODULE,
    behavior_version: int = 1,
) -> PolicyEngine:
    definition = _definition(
        rule,
        impact=impact,
        target=target,
        behavior_version=behavior_version,
    )
    return PolicyEngine(RuleRegistry.build((definition,)))


def _changed(module: str) -> ChangeSet:
    return ChangeSet(frozenset(), frozenset({ModuleId(module)}), frozenset())


def test_tracked_full_run_reports_exact_evaluation_count() -> None:
    rule = CountingRule()
    result = _engine(rule).run_tracked(_context(("app/a.py", "a = 1"), ("app/b.py", "b = 1")))
    assert result.state.full_rerun is True
    assert result.state.reused_evaluations == 0
    assert result.state.evaluated_evaluations == 2
    assert len(rule.calls) == 2


def test_unchanged_run_reuses_all_targets_with_zero_rule_calls() -> None:
    rule = CountingRule()
    engine = _engine(rule)
    context = _context(("app/a.py", "a = 1"), ("app/b.py", "b = 1"))
    previous = engine.run_tracked(context)
    rule.calls.clear()
    result = engine.run_incremental(
        context,
        context,
        previous,
        ChangeSet(frozenset(), frozenset(), frozenset()),
        ImpactGraph(frozenset()),
    )
    assert result.result == previous.result
    assert result.state.reused_evaluations == 2
    assert result.state.evaluated_evaluations == 0
    assert rule.calls == []


def test_self_impact_only_evaluates_touched_module() -> None:
    rule = CountingRule()
    engine = _engine(rule)
    old = _context(("app/a.py", "a = 1"), ("app/b.py", "b = 1"))
    new = _context(("app/a.py", "a = 2"), ("app/b.py", "b = 1"))
    previous = engine.run_tracked(old)
    rule.calls.clear()
    result = engine.run_incremental(
        new, old, previous, _changed("app.a"), ImpactGraph(frozenset({ModuleId("app.a")}))
    )
    assert result.result == engine.run(new)
    assert [target.module_id for target in rule.calls[:1]] == [ModuleId("app.a")]
    assert result.state.reused_evaluations == 1


def test_dependents_impact_evaluates_transitive_modules() -> None:
    rule = CountingRule()
    engine = _engine(rule, impact=ChangeImpact.DEPENDENTS)
    old = _context(("app/a.py", "a = 1"), ("app/b.py", "from app.a import a"))
    new = _context(("app/a.py", "a = 2"), ("app/b.py", "from app.a import a"))
    previous = engine.run_tracked(old)
    rule.calls.clear()
    impacted = frozenset({ModuleId("app.a"), ModuleId("app.b")})
    result = engine.run_incremental(new, old, previous, _changed("app.a"), ImpactGraph(impacted))
    assert result.result == engine.run(new)
    assert {target.module_id for target in rule.calls[:2]} == impacted
    assert result.state.reused_evaluations == 0


def test_project_rule_reuses_when_unchanged_and_reruns_on_change() -> None:
    rule = CountingRule()
    engine = _engine(rule, impact=ChangeImpact.PROJECT, target=RuleTarget.PROJECT)
    old = _context(("app/a.py", "a = 1"))
    previous = engine.run_tracked(old)
    rule.calls.clear()
    unchanged = engine.run_incremental(
        old,
        old,
        previous,
        ChangeSet(frozenset(), frozenset(), frozenset()),
        ImpactGraph(frozenset()),
    )
    assert unchanged.state.evaluated_evaluations == 0
    new = _context(("app/a.py", "a = 2"))
    changed = engine.run_incremental(
        new, old, previous, _changed("app.a"), ImpactGraph(frozenset({ModuleId("app.a")}))
    )
    assert changed.result == engine.run(new)
    assert changed.state.evaluated_evaluations == 1


def test_add_and_remove_targets_preserve_fresh_parity() -> None:
    rule = CountingRule()
    engine = _engine(rule)
    one = _context(("app/a.py", "a = 1"))
    two = _context(("app/a.py", "a = 1"), ("app/b.py", "b = 1"))
    previous = engine.run_tracked(one)
    rule.calls.clear()
    added_changes = ChangeSet(frozenset({ModuleId("app.b")}), frozenset(), frozenset())
    added = engine.run_incremental(
        two, one, previous, added_changes, ImpactGraph(added_changes.touched)
    )
    assert added.result == engine.run(two)
    assert added.state.reused_evaluations == 1
    rule.calls.clear()
    removed_changes = ChangeSet(frozenset(), frozenset(), frozenset({ModuleId("app.b")}))
    removed = engine.run_incremental(
        one, two, added, removed_changes, ImpactGraph(removed_changes.touched)
    )
    assert removed.result == engine.run(one)
    assert removed.state.reused_evaluations == 1


def test_raw_prior_result_conservatively_falls_back_to_full_run() -> None:
    rule = CountingRule()
    engine = _engine(rule)
    context = _context(("app/a.py", "a = 1"))
    raw = engine.run(context)
    rule.calls.clear()
    result = engine.run_incremental(
        context,
        context,
        raw,
        ChangeSet(frozenset(), frozenset(), frozenset()),
        ImpactGraph(frozenset()),
    )
    assert result.state.full_rerun is True
    assert len(rule.calls) == 1


def test_policy_setting_change_forces_full_rerun() -> None:
    rule = CountingRule()
    engine = _engine(rule)
    old = _context(("app/a.py", "a = 1"))
    previous = engine.run_tracked(old)
    new = replace(
        old,
        policy=replace(
            old.policy,
            rules=FrozenMap(
                (
                    *[(key, value) for key, value in old.policy.rules.items() if key != _RULE],
                    (_RULE, RuleSetting(RuleLevel.ADVISORY, FrozenMap())),
                )
            ),
        ),
    )
    rule.calls.clear()
    result = engine.run_incremental(
        new,
        old,
        previous,
        ChangeSet(frozenset(), frozenset(), frozenset()),
        ImpactGraph(frozenset()),
    )
    assert result.state.full_rerun is True
    assert len(rule.calls) == 1


def test_registry_behavior_version_change_forces_full_rerun() -> None:
    old_rule = CountingRule()
    old_engine = _engine(old_rule)
    context = _context(("app/a.py", "a = 1"))
    previous = old_engine.run_tracked(context)
    new_rule = CountingRule()
    new_engine = _engine(new_rule, behavior_version=2)
    result = new_engine.run_incremental(
        context,
        context,
        previous,
        ChangeSet(frozenset(), frozenset(), frozenset()),
        ImpactGraph(frozenset()),
    )
    assert result.state.full_rerun is True
    assert len(new_rule.calls) == 1


def test_capability_availability_change_forces_full_rerun() -> None:
    rule = CountingRule()
    engine = _engine(rule)
    source = make_source("app/a.py", "a = 1")
    new = _context((source.path.value, source.content))
    old = replace(new, model=SnapshotSemanticModel(analyze(source)))
    previous = engine.run_tracked(old)
    rule.calls.clear()
    result = engine.run_incremental(
        new,
        old,
        previous,
        ChangeSet(frozenset(), frozenset(), frozenset()),
        ImpactGraph(frozenset()),
    )
    assert result.state.full_rerun is True
    assert len(rule.calls) == 1


def test_syntax_completeness_change_forces_full_rerun() -> None:
    rule = CountingRule()
    engine = _engine(rule)
    old = _context(("app/a.py", "value = 1"))
    broken = _context(("app/a.py", "def broken(:"))
    previous = engine.run_tracked(old)
    rule.calls.clear()
    result = engine.run_incremental(
        broken,
        old,
        previous,
        _changed("app.a"),
        ImpactGraph(frozenset({ModuleId("app.a")})),
    )
    assert result.state.full_rerun is True
    assert result.result == engine.run(broken)


def test_prior_rule_failure_forces_full_rerun() -> None:
    engine = _engine(ExplodingRule())
    context = _context(("app/a.py", "a = 1"))
    previous = engine.run_tracked(context)
    assert previous.result.engine_issues
    result = engine.run_incremental(
        context,
        context,
        previous,
        ChangeSet(frozenset(), frozenset(), frozenset()),
        ImpactGraph(frozenset()),
    )
    assert result.state.full_rerun is True
    assert result.result == engine.run(context)


def test_unrelated_classification_change_forces_full_rerun() -> None:
    rule = CountingRule()
    engine = _engine(rule)
    sources = (("app/a.py", "a = 1"), ("app/b.py", "b = 1"))
    old = _context(*sources)
    new = _context(*sources, zones={"test": ("app/b.py",)})
    previous = engine.run_tracked(old)
    rule.calls.clear()
    result = engine.run_incremental(
        new, old, previous, _changed("app.a"), ImpactGraph(frozenset({ModuleId("app.a")}))
    )
    assert result.state.full_rerun is True
    assert len(rule.calls) == 1


def test_builtin_registry_incremental_result_matches_fresh_run() -> None:
    engine = PolicyEngine(builtin_rule_registry())
    old = make_context(
        analyze(
            make_source("app/a.py", "value = 1"),
            make_source("app/b.py", "from app.a import value"),
        ),
        roles={"service": ("app/**",)},
    )
    new = make_context(
        analyze(
            make_source("app/a.py", "value = 2"),
            make_source("app/b.py", "from app.a import value"),
        ),
        roles={"service": ("app/**",)},
    )
    previous = engine.run_tracked(old)
    impacted = frozenset({ModuleId("app.a"), ModuleId("app.b")})
    incremental = engine.run_incremental(
        new, old, previous, _changed("app.a"), ImpactGraph(impacted)
    )
    assert incremental.result == engine.run(new)
