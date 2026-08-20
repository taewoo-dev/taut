from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager

from taut.domain.facts import (
    ExecutionPhase,
    GuardKind,
    ScopeKind,
    SyntaxContext,
    SyntaxPosition,
)
from taut.domain.ids import FactId, SymbolId


class SyntaxContextStack:
    def __init__(self) -> None:
        self._guards = [GuardKind.UNCONDITIONAL]
        self._positions = [SyntaxPosition.BODY]
        self._parents: list[FactId | None] = [None]
        self._argument_names: list[str | None] = [None]
        self._argument_positions: list[int | None] = [None]

    def current(
        self,
        owner: SymbolId | None,
        scope_kind: ScopeKind,
        phase: ExecutionPhase,
    ) -> SyntaxContext:
        return SyntaxContext(
            lexical_owner=owner,
            scope_kind=scope_kind,
            position=self._positions[-1],
            execution_phase=phase,
            guard=self._guards[-1],
            parent_fact_id=self._parents[-1],
            argument_name=self._argument_names[-1],
            argument_position=self._argument_positions[-1],
        )

    @contextmanager
    def occurrence(
        self,
        *,
        position: SyntaxPosition | None = None,
        guard: GuardKind | None = None,
        parent: FactId | None = None,
        argument_name: str | None = None,
        argument_position: int | None = None,
    ) -> Generator[None]:
        self._positions.append(position or self._positions[-1])
        self._guards.append(self._merged_guard(guard or self._guards[-1]))
        self._parents.append(parent if parent is not None else self._parents[-1])
        self._argument_names.append(
            argument_name if argument_name is not None else self._argument_names[-1]
        )
        self._argument_positions.append(
            argument_position if argument_position is not None else self._argument_positions[-1]
        )
        try:
            yield
        finally:
            self._positions.pop()
            self._guards.pop()
            self._parents.pop()
            self._argument_names.pop()
            self._argument_positions.pop()

    def _merged_guard(self, guard: GuardKind) -> GuardKind:
        current = self._guards[-1]
        if GuardKind.TYPE_CHECKING_ONLY in (current, guard):
            return GuardKind.TYPE_CHECKING_ONLY
        if GuardKind.CONDITIONAL in (current, guard):
            return GuardKind.CONDITIONAL
        return GuardKind.UNCONDITIONAL
