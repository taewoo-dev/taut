from __future__ import annotations

import ast
import gc
import pickle
import weakref

import pytest
from tests.utils.builders import make_source

from taut.analysis.contracts import ResolverSettings, SourceInput
from taut.analysis.python import language_adapter
from taut.analysis.python.adapter import PythonFactExtractor
from taut.analysis.python.language_adapter import PythonAstAdapter
from taut.analysis.python.syntax_context import SyntaxContextStack
from taut.domain.facts import ExecutionPhase, GuardKind, ModuleFacts, ScopeKind
from taut.domain.ids import SymbolId


@pytest.mark.parametrize("fails", [False, True])
def test_adapter_releases_extractor_without_waiting_for_cycle_collection(
    monkeypatch: pytest.MonkeyPatch, fails: bool
) -> None:
    references: list[weakref.ReferenceType[PythonFactExtractor]] = []

    def capture(source: SourceInput, resolver: ResolverSettings) -> PythonFactExtractor:
        extractor = PythonFactExtractor(source, resolver)
        references.append(weakref.ref(extractor))
        return extractor

    def fail_extract(_self: PythonFactExtractor, _tree: ast.Module) -> ModuleFacts:
        raise RuntimeError("injected extractor failure")

    monkeypatch.setattr(language_adapter, "PythonFactExtractor", capture)
    if fails:
        monkeypatch.setattr(PythonFactExtractor, "extract", fail_extract)
    enabled = gc.isenabled()
    gc.disable()
    try:
        result = PythonAstAdapter().analyze_module(
            make_source("app/a.py", "def run():\n    print(1)\n")
        )
        assert bool(result.issues) is fails
        assert len(references) == 1 and references[0]() is None
        if not fails:
            assert result.facts.calls[0].ref.symbol == SymbolId("builtins.print")
    finally:
        if enabled:
            gc.enable()


def test_context_sharing_preserves_every_guard_and_scope() -> None:
    stack = SyntaxContextStack()
    owner = SymbolId("app.run")
    initial = stack.current(owner, ScopeKind.FUNCTION, ExecutionPhase.DEFERRED)
    assert stack.current(owner, ScopeKind.FUNCTION, ExecutionPhase.DEFERRED) is initial
    with stack.occurrence(guard=GuardKind.CONDITIONAL):
        guarded = stack.current(owner, ScopeKind.FUNCTION, ExecutionPhase.DEFERRED)
        assert guarded is not initial and guarded.guard is GuardKind.CONDITIONAL
    assert stack.current(owner, ScopeKind.FUNCTION, ExecutionPhase.DEFERRED) is initial
    assert (
        stack.current(SymbolId("app.other"), ScopeKind.FUNCTION, ExecutionPhase.DEFERRED)
        is not initial
    )


def test_pool_lifetime_does_not_mix_source_versions_and_survives_pickle() -> None:
    adapter = PythonAstAdapter()
    first = adapter.analyze_module(
        make_source("app/a.py", "def run():\n    print(1)\n    print(2)\n")
    )
    second = adapter.analyze_module(
        make_source("app/a.py", "def run():\n    print(3)\n    print(4)\n")
    )
    left, right = first.facts.calls
    assert left.context is right.context
    assert left.ref.symbol is right.ref.symbol
    assert left.ref.symbol == second.facts.calls[0].ref.symbol
    assert left.ref.symbol is not second.facts.calls[0].ref.symbol
    assert left.provenance.source_hash != second.facts.calls[0].provenance.source_hash
    restored = pickle.loads(pickle.dumps(first))
    assert restored == first
    assert restored.facts.calls[0].context is restored.facts.calls[1].context
    assert restored.facts.calls[0].ref.symbol is restored.facts.calls[1].ref.symbol
