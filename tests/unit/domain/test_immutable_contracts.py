from __future__ import annotations

import hashlib
from collections.abc import Callable

import pytest

from taut.domain.evaluations import (
    EvaluationReason,
    RuleTarget,
    RuleTargetRef,
    RuleVerdict,
)
from taut.domain.facts import (
    AnalysisStage,
    CompletenessState,
    FactKind,
    IncompleteReason,
    ModuleCompleteness,
    ResolutionState,
    SymbolRef,
)
from taut.domain.frozen import FrozenMap
from taut.domain.ids import FactId, ModuleId, RuleId, SnapshotId, SymbolId
from taut.domain.location import ProjectPath, SourceRange
from taut.domain.provenance import Provenance
from taut.domain.reports import CoverageReport
from taut.policy.rule import RuleEvaluation

DIGEST = hashlib.sha256(b"value").hexdigest()


def test_frozen_map_is_ordered_hashable_and_immutable() -> None:
    first = FrozenMap((("b", 2), ("a", 1)))
    second = FrozenMap((("a", 1), ("b", 2)))

    assert tuple(first) == ("a", "b")
    assert first == second
    assert hash(first) == hash(second)
    with pytest.raises(TypeError):
        first["a"] = 3  # type: ignore[index]
    with pytest.raises(ValueError, match="duplicate key"):
        FrozenMap((("a", 1), ("a", 2)))


@pytest.mark.parametrize(
    ("factory", "value"),
    [
        (ModuleId, "bad/module"),
        (SymbolId, "bad-symbol"),
        (RuleId, "time001"),
        (FactId, "abc"),
        (SnapshotId, "abc"),
        (ProjectPath, "/absolute.py"),
        (ProjectPath, "../outside.py"),
    ],
)
def test_identifiers_reject_invalid_values(factory: Callable[[str], object], value: str) -> None:
    with pytest.raises(ValueError):
        factory(value)


def test_python_identifiers_allow_unicode_names() -> None:
    assert ModuleId("서비스.결제") == ModuleId("서비스.결제")
    assert SymbolId("app.tests.test_결제_성공") == SymbolId("app.tests.test_결제_성공")


def test_source_range_validates_coordinates_and_displays_one_based() -> None:
    location = SourceRange(ProjectPath("app/a.py"), 0, 1, 0, 3)

    assert location.display_line == 1
    assert location.display_column == 2
    with pytest.raises(ValueError, match="negative"):
        SourceRange(ProjectPath("app/a.py"), -1, 0, 0, 0)
    with pytest.raises(ValueError, match="before"):
        SourceRange(ProjectPath("app/a.py"), 2, 0, 1, 0)


def test_symbol_ref_keeps_resolution_states_distinct() -> None:
    location = SourceRange(ProjectPath("app/a.py"), 0, 0, 0, 1)
    provenance = Provenance("python-ast", "1", DIGEST, location)
    resolved = SymbolRef(
        "dt.now",
        ResolutionState.RESOLVED,
        SymbolId("datetime.datetime.now"),
        (),
        provenance,
    )

    assert resolved.symbol == SymbolId("datetime.datetime.now")
    with pytest.raises(ValueError, match="one symbol"):
        SymbolRef("x", ResolutionState.RESOLVED, None, (), provenance)
    with pytest.raises(ValueError, match="at least two"):
        SymbolRef("x", ResolutionState.AMBIGUOUS, None, (SymbolId("a.x"),), provenance)
    with pytest.raises(ValueError, match="selected"):
        SymbolRef("x", ResolutionState.DYNAMIC, SymbolId("a.x"), (), provenance)


def test_module_completeness_rejects_contradictory_facts() -> None:
    with pytest.raises(ValueError, match="both available"):
        ModuleCompleteness(
            CompletenessState.PARTIAL,
            AnalysisStage.RESOLVED,
            frozenset({FactKind.CALL}),
            FrozenMap(((FactKind.CALL, IncompleteReason("x", "x")),)),
        )
    with pytest.raises(ValueError, match="facts_ready"):
        ModuleCompleteness(
            CompletenessState.COMPLETE,
            AnalysisStage.RESOLVED,
            frozenset(FactKind),
            FrozenMap(),
        )


def test_rule_target_and_evaluation_invariants() -> None:
    module_id = ModuleId("app.service")
    target = RuleTargetRef(RuleTarget.MODULE, module_id=module_id)
    reason = EvaluationReason("missing", "missing facts")

    evaluation = RuleEvaluation(RuleId("ARCH001"), target, RuleVerdict.INDETERMINATE, (), reason)
    assert evaluation.reason == reason
    with pytest.raises(ValueError, match="requires module_id"):
        RuleTargetRef(RuleTarget.MODULE)
    with pytest.raises(ValueError, match="requires at least one"):
        RuleEvaluation(RuleId("ARCH001"), target, RuleVerdict.FAIL, ())
    with pytest.raises(ValueError, match="requires a reason"):
        RuleEvaluation(RuleId("ARCH001"), target, RuleVerdict.INDETERMINATE, ())


def test_coverage_report_enforces_accounting_equation() -> None:
    coverage = CoverageReport(1, 3, 1, 1, 1, 0, ())
    assert coverage.total_targets == 3
    with pytest.raises(ValueError, match="one coverage issue"):
        CoverageReport(1, 1, 0, 0, 0, 1, ())
