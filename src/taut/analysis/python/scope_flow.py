from __future__ import annotations

import ast
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from taut.domain.facts import GuardKind, ResolutionState, SymbolRef
from taut.domain.ids import FactId, SymbolId


@dataclass(frozen=True)
class BindingState:
    candidates: frozenset[SymbolId]
    definite: bool = True
    binding_ids: frozenset[FactId] = frozenset()


FlowSnapshot = tuple[
    dict[SymbolId | None, dict[str, SymbolId]],
    dict[SymbolId | None, dict[str, BindingState]],
]
GuardedVisitor = Callable[[Sequence[ast.stmt], GuardKind, bool], object]


class PythonScopeFlow:
    current_scope: SymbolId | None
    bindings: dict[SymbolId | None, dict[str, SymbolId]]
    binding_states: dict[SymbolId | None, dict[str, BindingState]]
    _shared_flow_maps: set[int]
    _type_checking_depth: int
    _type_resolution_depth: int

    def _resolve(self, node: ast.AST) -> SymbolRef:
        raise NotImplementedError

    def _declare_assignment(self, name: str) -> None:
        raise NotImplementedError

    def _flow_snapshot(self) -> FlowSnapshot:
        bindings = dict(self.bindings)
        states = dict(self.binding_states)
        self._shared_flow_maps.update(id(values) for values in bindings.values())
        self._shared_flow_maps.update(id(values) for values in states.values())
        return bindings, states

    def _restore_flow(self, snapshot: FlowSnapshot) -> None:
        bindings, states = snapshot
        self.bindings.clear()
        self.bindings.update(bindings)
        self.binding_states.clear()
        self.binding_states.update(states)

    def _prepare_flow_write(self, scope: SymbolId | None) -> None:
        bindings = self.bindings[scope]
        if id(bindings) in self._shared_flow_maps:
            self.bindings[scope] = dict(bindings)
        states = self.binding_states[scope]
        if id(states) in self._shared_flow_maps:
            self.binding_states[scope] = dict(states)

    def _merge_flows(self, snapshots: Sequence[FlowSnapshot]) -> None:
        if not snapshots:
            self.bindings.clear()
            self.binding_states.clear()
            return
        first_bindings, first_states = snapshots[0]
        if all(
            bindings == first_bindings and states == first_states
            for bindings, states in snapshots[1:]
        ):
            self._restore_flow(snapshots[0])
            return
        scopes: set[SymbolId | None] = set()
        for _, states in snapshots:
            scopes.update(states)
        merged_bindings: dict[SymbolId | None, dict[str, SymbolId]] = {}
        merged_states: dict[SymbolId | None, dict[str, BindingState]] = {}
        for scope in scopes:
            names: set[str] = set()
            for _, states in snapshots:
                names.update(states.get(scope, {}))
            scope_bindings: dict[str, SymbolId] = {}
            scope_states: dict[str, BindingState] = {}
            for name in names:
                path_states = [states.get(scope, {}).get(name) for _, states in snapshots]
                candidates = frozenset(
                    candidate
                    for state in path_states
                    if state is not None
                    for candidate in state.candidates
                )
                binding_ids = frozenset(
                    binding_id
                    for state in path_states
                    if state is not None
                    for binding_id in state.binding_ids
                )
                definite = all(state is not None and state.definite for state in path_states)
                scope_states[name] = BindingState(candidates, definite, binding_ids)
                if len(candidates) == 1:
                    scope_bindings[name] = next(iter(candidates))
            merged_bindings[scope] = scope_bindings
            merged_states[scope] = scope_states
        self.bindings.clear()
        self.bindings.update(merged_bindings)
        self.binding_states.clear()
        self.binding_states.update(merged_states)

    def _enter_type_checking(self) -> None:
        self._type_checking_depth += 1

    def _leave_type_checking(self) -> None:
        self._type_checking_depth -= 1

    def _enter_type_resolution(self) -> None:
        self._type_resolution_depth += 1

    def _leave_type_resolution(self) -> None:
        self._type_resolution_depth -= 1

    def _branch_result(
        self,
        baseline: FlowSnapshot,
        statements: Sequence[ast.stmt],
        guarded: GuardedVisitor,
        guard: GuardKind = GuardKind.CONDITIONAL,
        type_checking: bool = False,
    ) -> FlowSnapshot:
        self._restore_flow(baseline)
        guarded(statements, guard, type_checking)
        return self._flow_snapshot()

    def _visit_if_flow(
        self, node: ast.If, visit: Callable[[ast.AST], object], guarded: GuardedVisitor
    ) -> None:
        visit(node.test)
        test_ref = self._resolve(node.test)
        type_checking = test_ref.state is ResolutionState.RESOLVED and test_ref.symbol == SymbolId(
            "typing.TYPE_CHECKING"
        )
        baseline = self._flow_snapshot()
        body = self._branch_result(
            baseline,
            node.body,
            guarded,
            GuardKind.TYPE_CHECKING_ONLY if type_checking else GuardKind.CONDITIONAL,
            type_checking,
        )
        alternative = (
            self._branch_result(baseline, node.orelse, guarded) if node.orelse else baseline
        )
        self._merge_flows([alternative] if type_checking else [body, alternative])

    def _visit_loop_flow(
        self,
        node: ast.For | ast.AsyncFor | ast.While,
        visit: Callable[[ast.AST], object],
        guarded: GuardedVisitor,
    ) -> None:
        visit(node.iter if isinstance(node, (ast.For, ast.AsyncFor)) else node.test)
        baseline = self._flow_snapshot()
        self._restore_flow(baseline)
        if isinstance(node, (ast.For, ast.AsyncFor)):
            visit(node.target)
        guarded(node.body, GuardKind.CONDITIONAL, False)
        body = self._flow_snapshot()
        zero = self._branch_result(baseline, node.orelse, guarded) if node.orelse else baseline
        if node.orelse:
            break_path = body
            self._restore_flow(body)
            guarded(node.orelse, GuardKind.CONDITIONAL, False)
            body = self._flow_snapshot()
            self._merge_flows([body, zero, break_path])
        else:
            self._merge_flows([body, zero])

    def _visit_try_flow(
        self,
        node: ast.Try | ast.TryStar,
        visit: Callable[[ast.AST], object],
        guarded: GuardedVisitor,
    ) -> None:
        baseline = self._flow_snapshot()
        self._restore_flow(baseline)
        for statement in (*node.body, *node.orelse):
            visit(statement)
        paths = [self._flow_snapshot()]
        for handler in node.handlers:
            self._restore_flow(baseline)
            if handler.type is not None:
                visit(handler.type)
            if handler.name:
                self._declare_assignment(handler.name)
                record_exception = getattr(self, "_record_exception_binding", None)
                if record_exception is not None:
                    record_exception(handler)
            guarded(handler.body, GuardKind.CONDITIONAL, False)
            paths.append(self._flow_snapshot())
        self._merge_flows(paths)
        for statement in node.finalbody:
            visit(statement)

    def _visit_match_flow(
        self, node: ast.Match, visit: Callable[[ast.AST], object], guarded: GuardedVisitor
    ) -> None:
        visit(node.subject)
        baseline = self._flow_snapshot()
        paths: list[FlowSnapshot] = []
        exhaustive = False
        for case in node.cases:
            self._restore_flow(baseline)
            for child in ast.walk(case.pattern):
                if isinstance(child, (ast.MatchAs, ast.MatchStar)) and child.name:
                    self._declare_assignment(child.name)
                elif isinstance(child, ast.MatchMapping) and child.rest:
                    self._declare_assignment(child.rest)
            visit(case.pattern)
            if case.guard is not None:
                visit(case.guard)
            guarded(case.body, GuardKind.CONDITIONAL, False)
            paths.append(self._flow_snapshot())
            exhaustive = exhaustive or (
                isinstance(case.pattern, ast.MatchAs)
                and case.pattern.pattern is None
                and case.guard is None
            )
        if not exhaustive:
            paths.append(baseline)
        self._merge_flows(paths)
