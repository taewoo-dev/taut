import ast
from dataclasses import replace

import pytest
from tests.utils.builders import analyze, make_source

from taut.analysis.project_relations import build_project_relations
from taut.analysis.python.scope_flow import PythonScopeFlow
from taut.domain.facts import (
    AnalysisStage,
    CompletenessState,
    FactKind,
    IncompleteReason,
    ModuleCompleteness,
    ResolutionState,
)
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId
from taut.domain.relations import BindingKind, ModuleRelations, ProjectRelations, UseEdge
from taut.domain.snapshot import AnalysisSnapshot


def _uses(code: str) -> tuple[AnalysisSnapshot, tuple[UseEdge, ...]]:
    snapshot = analyze(make_source("app/exact.py", code))
    return snapshot, tuple(
        edge for edge in snapshot.relations.use_edges if edge.ref.written_name == "x"
    )


def test_redefinition_and_shadowing_keep_exact_binding_ids() -> None:
    snapshot, _ = _uses("x = 1\nx = 2\nprint(x)\ndef f():\n    x = 3\n    return x\n")
    assignments = [
        binding
        for binding in snapshot.relations.bindings
        if binding.local_name == "x" and binding.kind is BindingKind.ASSIGNMENT
    ]
    assert len(assignments) == 3
    module_use = next(
        edge
        for edge in snapshot.relations.use_edges
        if edge.ref.written_name == "x" and edge.location.start_line == 2
    )
    function_use = next(
        edge
        for edge in snapshot.relations.use_edges
        if edge.ref.written_name == "x" and edge.location.start_line == 5
    )
    assert module_use.binding_id == assignments[1].id
    assert function_use.binding_id == assignments[2].id


def test_conditional_relations_preserve_one_or_many_candidates() -> None:
    _, one = _uses("if flag:\n    x = 1\nprint(x)\n")
    assert one[0].ref.state is ResolutionState.CONDITIONAL
    assert len(one[0].candidate_binding_ids) == 1
    _, many = _uses("if a:\n    x = 1\nelse:\n    x = 2\nprint(x)\n")
    assert many[0].ref.state is ResolutionState.RESOLVED
    assert many[0].binding_id is None
    assert len(many[0].candidate_binding_ids) == 2


def test_match_or_and_unresolved_are_traceable_without_guesses() -> None:
    _, uses = _uses("match value:\n    case A(x) | B(x):\n        pass\nprint(x)\n")
    assert uses[0].ref.state is ResolutionState.CONDITIONAL
    # Python's OR-pattern capture is one lexical binding shared by both alternatives.
    assert len(uses[0].candidate_binding_ids) == 1
    _, unresolved = _uses("print(x)\n")
    assert unresolved[0].ref.state is ResolutionState.UNRESOLVED
    assert unresolved[0].binding_id is None
    assert unresolved[0].candidate_binding_ids == ()


def test_project_relation_builder_does_not_recover_by_local_name() -> None:
    snapshot = analyze(make_source("app/exact.py", "x = 1\nprint(x)\n"))
    module = snapshot.modules[ModuleId("app.exact")]
    rebuilt = build_project_relations(FrozenMap({module.module.id: module}), snapshot.project)
    assert rebuilt.bindings == ()
    assert rebuilt.use_edges == ()


def test_relation_invariants_reject_invalid_candidate_provenance() -> None:
    snapshot, uses = _uses("x = 1\nprint(x)\n")
    edge = uses[0]
    binding = next(item for item in snapshot.relations.bindings if item.id == edge.binding_id)
    with pytest.raises(ValueError, match="selected binding"):
        ModuleRelations((binding,), (replace(edge, candidate_binding_ids=(edge.occurrence_id,)),))
    with pytest.raises(ValueError, match="known bindings"):
        ProjectRelations(
            (binding,),
            snapshot.project.import_edges,
            (replace(edge, candidate_binding_ids=(binding.id, edge.occurrence_id)),),
        )


def test_completeness_rejects_invalid_combinations() -> None:
    with pytest.raises(ValueError, match="complete module"):
        ModuleCompleteness(
            CompletenessState.COMPLETE, AnalysisStage.RESOLVED, frozenset(), FrozenMap()
        )
    with pytest.raises(ValueError, match="failed module"):
        ModuleCompleteness(
            CompletenessState.FAILED, AnalysisStage.RESOLVED, frozenset(), FrozenMap()
        )
    with pytest.raises(ValueError, match="both available"):
        ModuleCompleteness(
            CompletenessState.PARTIAL,
            AnalysisStage.RESOLVED,
            frozenset({FactKind.CALL}),
            FrozenMap({FactKind.CALL: IncompleteReason("x", "x")}),
        )


def test_relation_invariants_reject_duplicate_and_cross_module_edges() -> None:
    snapshot, uses = _uses("x = 1\nprint(x)\n")
    edge = uses[0]
    binding = next(item for item in snapshot.relations.bindings if item.id == edge.binding_id)
    with pytest.raises(ValueError, match="unique"):
        ModuleRelations((binding, binding), ())
    with pytest.raises(ValueError, match="unique"):
        ModuleRelations((binding,), (edge, edge))
    _, branch_uses = _uses("if a:\n    x = 1\nelse:\n    x = 2\nprint(x)\n")
    with pytest.raises(ValueError, match="sorted"):
        ModuleRelations(
            (binding,),
            (
                replace(
                    edge,
                    binding_id=None,
                    candidate_binding_ids=tuple(reversed(branch_uses[0].candidate_binding_ids)),
                ),
            ),
        )
    other = replace(binding, module_id=ModuleId("app.other"))
    with pytest.raises(ValueError, match="known bindings"):
        ProjectRelations(
            (binding,),
            snapshot.project.import_edges,
            (replace(edge, binding_id=edge.occurrence_id),),
        )
    with pytest.raises(ValueError, match="same module"):
        ProjectRelations(
            (other,),
            snapshot.project.import_edges,
            (replace(edge, binding_id=other.id, candidate_binding_ids=(other.id,)),),
        )
    with pytest.raises(ValueError, match="binding ids"):
        ProjectRelations((binding, binding), snapshot.project.import_edges, ())
    with pytest.raises(ValueError, match="use occurrence ids"):
        ProjectRelations((binding,), snapshot.project.import_edges, (edge, edge))
    with pytest.raises(ValueError, match="candidates"):
        ProjectRelations(
            (other,),
            snapshot.project.import_edges,
            (replace(edge, binding_id=None, candidate_binding_ids=(other.id,)),),
        )


def test_empty_relation_collections_are_valid() -> None:
    assert ModuleRelations() == ModuleRelations((), ())
    assert ProjectRelations((), (), ()) == ProjectRelations((), (), ())


def test_scope_flow_protocol_methods_remain_abstract() -> None:
    flow = PythonScopeFlow()
    with pytest.raises(NotImplementedError):
        flow._resolve(ast.Name(id="x"))
    with pytest.raises(NotImplementedError):
        flow._declare_assignment("x")
