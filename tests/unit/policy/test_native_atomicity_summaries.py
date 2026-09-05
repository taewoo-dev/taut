from __future__ import annotations

import gc
import random
import weakref
from dataclasses import replace
from importlib.util import find_spec
from types import ModuleType
from typing import cast

import pytest
from tests.utils.builders import analyze, make_context, make_source

from taut.domain.facts import ResolutionState
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, SymbolId
from taut.policy.atomicity_summaries import AtomicitySummaryState, WriteRange
from taut.policy.native_atomicity_summaries import (
    AtomicBatch,
    AtomicContribution,
    AtomicFactory,
    NativeAtomicState,
    build_native_atomicity_summary_state,
)
from taut.policy.native_function_summaries import native_extension

native = pytest.mark.skipif(find_spec("_taut_summary_core") is None, reason="optional native wheel")


@native
@pytest.mark.parametrize("seed", [17, 83, 251])
def test_random_atomicity_four_paths(seed: int) -> None:
    rng = random.Random(seed)
    old_python: AtomicitySummaryState | None = None
    old_rust: AtomicitySummaryState | None = None
    for revision in range(100):
        count = rng.randrange(2, 18)
        code = (
            "from tortoise.models import Model\n"
            "from tortoise.transactions import atomic, in_transaction\n"
            "class User(Model): pass\n"
        )
        for i in range(count):
            if rng.randrange(4) == 0:
                code += "@atomic()\n"
            code += f"def f{i}():\n"
            indent = "    "
            if rng.randrange(4) == 0:
                code += "    with in_transaction():\n"
                indent = "        "
            calls = [f"f{rng.randrange(count)}()" for _ in range(rng.randrange(3))]
            calls += ["User.create()" for _ in range(rng.randrange(3))]
            code += indent + ("; ".join(calls) or "pass") + "\n"
        context = make_context(
            analyze(make_source("m.py", code), make_source("stable.py", "def f(): pass\n")),
            roles={"service": ("*.py",)},
        )
        fresh = context.atomicity_summary_state
        python = replace(
            context,
            prior_atomicity_summary_state=old_python,
            atomicity_summary_invalidated_modules=frozenset({ModuleId("m")}),
        ).atomicity_summary_state
        rust_fresh = replace(context, summary_backend="rust").atomicity_summary_state
        rust = replace(
            context,
            summary_backend="rust",
            prior_atomicity_summary_state=old_rust,
            atomicity_summary_invalidated_modules=frozenset({ModuleId("m")}),
        ).atomicity_summary_state
        for state in (python, rust_fresh, rust):
            assert state.summaries == fresh.summaries, (seed, revision)
            assert state.contributions == fresh.contributions, (seed, revision)
            assert state.modules == fresh.modules
        if old_rust is not None:
            assert old_python is not None
            assert old_rust.summaries == old_python.summaries
        old_python, old_rust = python, rust


@native
def test_native_atomicity_cross_module_removal_and_lifetime() -> None:
    old: AtomicitySummaryState | None = None
    for body in ("User.create()", "pass", "User.create()"):
        context = make_context(
            analyze(
                make_source("a.py", "from b import write\ndef run(): write(); write()\n"),
                make_source(
                    "b.py",
                    "from tortoise.models import Model\nclass User(Model): pass\n"
                    f"def write(): {body}\n",
                ),
            ),
            roles={"service": ("*.py",)},
        )
        current = replace(
            context,
            summary_backend="rust",
            prior_atomicity_summary_state=old,
            atomicity_summary_invalidated_modules=frozenset({ModuleId("b")}),
        ).atomicity_summary_state
        assert current.summaries == context.atomicity_summary_state.summaries
        assert current.summaries[SymbolId("a.run")] == (
            WriteRange() if body == "pass" else WriteRange(2, 2)
        )
        if old is not None:
            ref = weakref.ref(old.native_handle)
            del old
            gc.collect()
            assert ref() is None
        old = current


class RecordedAtomic:
    processed_functions = 1
    compute_seconds = 0.0

    def __init__(self) -> None:
        self.batch: AtomicBatch | None = None

    def build(self, batch: AtomicBatch) -> NativeAtomicState:
        self.batch = batch
        return self

    def advance(self, changed: list[str], batch: AtomicBatch) -> NativeAtomicState:
        assert changed == ["m"]
        return self.build(batch)

    def export(self) -> list[tuple[str, tuple[int, int]]]:
        return [("m.f", (1, 1))]

    def export_contributions(self) -> list[tuple[str, list[AtomicContribution]]]:
        return [("m.f", [((1, 1), None, [])])]


class AtomicExtension(ModuleType):
    AtomicState: RecordedAtomic


def test_atomicity_batch_boundary_without_extension(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = RecordedAtomic()
    extension = AtomicExtension("recorded")
    extension.AtomicState = recorder

    def factory() -> ModuleType:
        return extension

    monkeypatch.setattr("taut.policy.native_atomicity_summaries.native_extension", factory)
    context = make_context(
        analyze(
            make_source(
                "m.py",
                "from tortoise.models import Model\nclass User(Model): pass\n"
                "def f(): User.create()\n",
            )
        ),
        roles={"service": ("*.py",)},
    )
    state = build_native_atomicity_summary_state(context)
    assert recorder.batch is not None
    assert recorder.batch[0] == [("m.f", "m", [])]
    assert recorder.batch[2] == [("m", ["User"])]
    assert len(state.contributions) == 1
    assert list(state.contributions) == [SymbolId("m.f")]
    assert state.contributions[SymbolId("m.f")][0].direct == WriteRange(1, 1)
    next_state = build_native_atomicity_summary_state(context, state, frozenset({ModuleId("m")}))
    assert next_state.summaries == state.summaries


@native
@pytest.mark.parametrize("boundary", ["decorator", "context"])
def test_transaction_boundary_requires_exact_symbol(boundary: str) -> None:
    prefix = (
        "from tortoise.models import Model\nclass User(Model): pass\nfrom vendor import guard\n"
    )
    body = (
        "@guard.child\ndef f(): User.create(); User.create()\n"
        if boundary == "decorator"
        else "def f():\n    with guard.child():\n        User.create(); User.create()\n"
    )
    context = make_context(
        analyze(make_source("m.py", prefix + body)), roles={"service": ("*.py",)}
    )
    policy = replace(
        context.policy,
        transaction_boundary_decorators=frozenset({SymbolId("vendor.guard")}),
        transaction_boundary_contexts=frozenset({SymbolId("vendor.guard")}),
    )
    context = replace(context, policy=policy)
    assert context.atomicity_summary_state.summaries[SymbolId("m.f")] == WriteRange(2, 2)
    assert (
        replace(context, summary_backend="rust").atomicity_summary_state.summaries
        == context.atomicity_summary_state.summaries
    )


@native
def test_ambiguous_callees_only_raise_upper_bound() -> None:
    snapshot = analyze(
        make_source(
            "m.py",
            "from tortoise.models import Model\n"
            "class User(Model): pass\ndef a(): User.create()\n"
            "def b(): pass\ndef run(): unknown()\n",
        )
    )
    module_id = ModuleId("m")
    module = snapshot.modules[module_id]
    calls = tuple(
        replace(
            call,
            ref=replace(
                call.ref,
                state=ResolutionState.AMBIGUOUS,
                symbol=None,
                candidates=(SymbolId("m.a"), SymbolId("m.b")),
            ),
        )
        if call.ref.written_name == "unknown"
        else call
        for call in module.calls
    )
    snapshot = replace(snapshot, modules=FrozenMap({module_id: replace(module, calls=calls)}))
    context = make_context(snapshot, roles={"service": ("*.py",)})
    expected = context.atomicity_summary_state
    assert expected.summaries[SymbolId("m.run")] == WriteRange(0, 1)
    result = replace(context, summary_backend="rust").atomicity_summary_state
    assert result.summaries == expected.summaries
    assert result.contributions == expected.contributions


@native
def test_bad_columns_leave_previous_atomicity_state_usable() -> None:
    factory = cast(AtomicFactory, native_extension().AtomicState)
    initial: AtomicBatch = ([("m.f", "m", [])], ([], [], [], [], [], [], [], []), [], [], [])
    old = factory.build(initial)
    broken: AtomicBatch = ([], (["m.f"], [], [], [], [], [], [], []), [], [], [])
    with pytest.raises(ValueError, match="column lengths"):
        old.advance(["m"], broken)
    assert old.export() == [("m.f", (0, 0))]
    assert old.advance(["m"], initial).export() == old.export()
