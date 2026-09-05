from __future__ import annotations

import gc
import random
import weakref
from dataclasses import replace
from functools import partial
from importlib.util import find_spec
from pathlib import Path
from typing import cast

import pytest
from tests.utils.builders import analyze, make_source
from tests.utils.builders import make_context as build_context

from taut.check_service import CheckRequest, ResidentCheckSession, run_check_request
from taut.configuration.catalog import AccessPath, CatalogEntry, Effect
from taut.domain.ids import ModuleId, SymbolId
from taut.policy.function_summaries import FunctionSummaryState
from taut.policy.native_function_summaries import (
    NativeDirectView,
    NativeGraphView,
    NativeRow,
    NativeState,
    NativeValue,
    build_native_function_summary_state,
    decode_summary,
    encode_summary,
    native_factory,
    validate_summary_backend,
)

make_context = partial(build_context, roles={"service": ("*.py",)})

native = pytest.mark.skipif(find_spec("_taut_summary_core") is None, reason="optional native wheel")


def test_missing_or_incompatible_native(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("taut.policy.native_function_summaries._extension", None)
    with pytest.raises(RuntimeError, match="requires"):
        native_factory()
    monkeypatch.setattr("taut.policy.native_function_summaries._extension", object())
    with pytest.raises(RuntimeError, match="incompatible"):
        native_factory()


@native
@pytest.mark.parametrize("seed", [17, 83, 251])
def test_random_revisions_match_four_paths(seed: int) -> None:
    rng = random.Random(seed)
    python_prior: FunctionSummaryState | None = None
    rust_prior: FunctionSummaryState | None = None
    for revision in range(100):
        count = rng.randrange(1, 22)
        code = "import time\n"
        for i in range(count):
            calls = [f"f{rng.randrange(count)}()" for _ in range(rng.randrange(4))]
            calls += rng.sample(
                ["time.sleep(0)", "dict()", "vars()", "time.time()"], rng.randrange(5)
            )
            code += f"def f{i}():\n    " + ("; ".join(calls) or "pass") + "\n"
        context = make_context(analyze(make_source("m.py", code)))
        expected = context.function_summary_state
        python_incremental = replace(
            context,
            prior_function_summary_state=python_prior,
            function_summary_invalidated_modules=frozenset({ModuleId("m")}),
        ).function_summary_state
        rust_fresh = replace(context, summary_backend="rust").function_summary_state
        rust_incremental = replace(
            context,
            summary_backend="rust",
            prior_function_summary_state=rust_prior,
            function_summary_invalidated_modules=frozenset({ModuleId("m")}),
        ).function_summary_state
        for result in (python_incremental, rust_fresh, rust_incremental):
            assert result.summaries == expected.summaries, (seed, revision)
            assert result.graph == expected.graph
            assert result.direct == expected.direct
        if rust_prior is not None:
            assert python_prior is not None
            assert rust_prior.summaries == python_prior.summaries
        python_prior, rust_prior = python_incremental, rust_incremental


@native
@pytest.mark.parametrize(
    "body",
    [
        "wrapped(); send()",
        "wrapped()",
        "(lambda: time.sleep(0))()",
        "map(lambda _: time.sleep(0), [1])",
        "vars(); dict(); session()",
    ],
)
def test_access_callbacks_providers_and_bulk(body: str) -> None:
    context = make_context(
        analyze(
            make_source(
                "m.py",
                "import time\n"
                "from vendor import wrapped, send, session\n"
                f"def f(): {body}\ndef g(): f()\n",
            )
        ),
        extra_catalog_entries=(
            CatalogEntry(
                SymbolId("vendor.wrapped"),
                frozenset({Effect.EXTERNAL_CALL}),
                AccessPath.APPROVED_WRAPPER,
            ),
            CatalogEntry(
                SymbolId("vendor.send"), frozenset({Effect.EXTERNAL_CALL}), AccessPath.DIRECT
            ),
        ),
    )
    context = replace(
        context,
        policy=replace(
            context.policy, transaction_session_providers=frozenset({SymbolId("vendor.session")})
        ),
    )
    assert replace(context, summary_backend="rust").function_summaries == context.function_summaries


@native
def test_native_failure_and_old_revision_lifetime() -> None:
    factory = native_factory()
    old = factory.build([("m.f", "m", [], (1, 1, [], [], 0))])
    with pytest.raises(ValueError):
        old.advance(["m"], [("m.f", "m", [], (256, 0, [], [], 0))])
    new = old.advance(["m"], [])
    assert new.export() == []
    assert old.export()[0][1][0] == 1
    context = replace(
        make_context(analyze(make_source("m.py", "def f(): pass\n"))), summary_backend="rust"
    )
    state = context.function_summary_state
    ref = weakref.ref(state)
    del context, state
    gc.collect()
    assert ref() is None


@native
def test_session_reports_edits_reset_and_close(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[tool.taut]\nschema_version = 5\nstrict = false\n")
    source = tmp_path / "m.py"
    variants = ["import time\ndef f(): time.sleep(0)\n", "def f(:\n", "def g(): pass\n", ""]
    with (
        ResidentCheckSession(tmp_path, summary_backend="rust") as rust,
        ResidentCheckSession(tmp_path) as python,
    ):
        assert rust.summary_statistics == ()
        for iteration in range(12):
            source.write_text(variants[iteration % len(variants)])
            for fmt in ("text", "json"):
                request = CheckRequest(tmp_path, output_format=fmt)
                expected = run_check_request(request)
                for result in (
                    python.check(request),
                    rust.check(request),
                    run_check_request(request, summary_backend="rust"),
                ):
                    assert (result.report, result.stdout, result.stderr, result.exit_code) == (
                        expected.report,
                        expected.stdout,
                        expected.stderr,
                        expected.exit_code,
                    )
            assert python.summary_statistics == ()
            if rust.summary_statistics:
                assert len(rust.summary_statistics) == 4
            if iteration == 5:
                source.unlink()
                assert rust.check(request).stdout == run_check_request(request).stdout
                rust.reset()
        rust.reset()
    with pytest.raises(RuntimeError, match="closed"):
        rust.check(CheckRequest(tmp_path))
    validate_summary_backend("python")


@native
def test_incremental_reuses_unchanged_module() -> None:
    context = make_context(
        analyze(make_source("a.py", "def f(): pass\n"), make_source("b.py", "def g(): pass\n"))
    )
    old = replace(context, summary_backend="rust").function_summary_state
    new = replace(
        context,
        summary_backend="rust",
        prior_function_summary_state=old,
        function_summary_invalidated_modules=frozenset({ModuleId("a")}),
    ).function_summary_state
    assert new.summaries == old.summaries
    assert new.reused_components == 2
    assert cast(NativeState, new.native_handle).stats() == (2, 0, 0, 1)


@native
@pytest.mark.parametrize("seed", [17, 83, 251])
def test_random_full_reports_four_paths(tmp_path: Path, seed: int) -> None:
    rng = random.Random(seed)
    configuration = tmp_path / "pyproject.toml"
    configuration.write_text("[tool.taut]\nschema_version = 5\nstrict = false\n")
    source = tmp_path / "m.py"
    extra = tmp_path / "extra.py"
    variants = [
        "import time\nasync def f(): time.sleep(0)\n",
        "def f(:\n",
        "def renamed(): return 1\n",
        "import asyncio, time\nasync def f(): await asyncio.to_thread(time.sleep, 0)\n",
        "import time\ndef helper(cb): cb()\nasync def f(): helper(lambda: time.sleep(0))\n",
        "from extra import f\ndef g(): f()\n",
        "",
    ]
    with (
        ResidentCheckSession(tmp_path, summary_backend="rust") as rust,
        ResidentCheckSession(tmp_path) as python,
    ):
        for iteration in range(100):
            source.write_text(rng.choice(variants))
            if rng.randrange(3):
                extra.write_text("import time\ndef f(): time.sleep(0)\n")
            else:
                extra.unlink(missing_ok=True)
            if iteration == 50:
                configuration.write_text(
                    "[tool.taut]\nschema_version = 5\nstrict = false\n"
                    '[tool.taut.roles]\nservice = ["*.py"]\n'
                    '[tool.taut.allow]\nservice = ["service"]\n'
                )
            for fmt in ("text", "json"):
                request = CheckRequest(tmp_path, output_format=fmt)
                expected = run_check_request(request)
                for result in (
                    python.check(request),
                    rust.check(request),
                    run_check_request(request, summary_backend="rust"),
                ):
                    assert (result.report, result.stdout, result.stderr, result.exit_code) == (
                        expected.report,
                        expected.stdout,
                        expected.stderr,
                        expected.exit_code,
                    ), (seed, iteration, fmt)


@native
def test_native_snapshots_do_not_retain_history() -> None:
    old = native_factory().build([("m.f", "m", [], (1, 1, [], [], 0))])
    old_ref = weakref.ref(old)
    current = old.advance(["m"], [("m.g", "m", [], (0, 0, [], [], 0))])
    del old
    gc.collect()
    assert old_ref() is None
    assert current.stats()[0] == 1
    for _ in range(100):
        current = current.advance(["m"], [("m.g", "m", [], (0, 0, [], [], 0))])
    assert current.stats() == (1, 0, 0, 1)


class RecordedNative:
    reused_components = 0
    recomputed_components = 1
    compute_seconds = 0.0

    def __init__(self) -> None:
        self.rows: list[NativeRow] = []
        self.changed: list[str] = []
        self.exports = 0

    def build(self, rows: list[NativeRow]) -> NativeState:
        self.rows = rows
        return self

    def advance(self, changed_modules: list[str], rows: list[NativeRow]) -> NativeState:
        self.changed = changed_modules
        return self.build(rows)

    def export(self) -> list[tuple[str, NativeValue]]:
        return [(name, value) for name, _, _, value in self.rows]

    def export_compact(self) -> tuple[list[NativeValue], list[tuple[str, int]]]:
        return (
            [value for _, _, _, value in self.rows],
            [(name, i) for i, (name, _, _, _) in enumerate(self.rows)],
        )

    def export_direct(self) -> list[tuple[str, NativeValue]]:
        self.exports += 1
        return self.export()

    def export_graph(self) -> list[tuple[str, list[str]]]:
        self.exports += 1
        return [(name, calls) for name, _, calls, _ in self.rows]

    def stats(self) -> tuple[int, int, int, int]:
        return (len(self.rows), 0, 0, 1)


def test_native_batch_and_lazy_export_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = RecordedNative()

    def factory() -> RecordedNative:
        return recorder

    monkeypatch.setattr("taut.policy.native_function_summaries.native_factory", factory)
    context = make_context(analyze(make_source("m.py", "import time\ndef f(): time.sleep(0)\n")))
    state = build_native_function_summary_state(context)
    assert recorder.rows == [("m.f", "m", [], (2, 2, [], [], 0))]
    direct, graph = NativeDirectView(recorder), NativeGraphView(recorder)
    assert len(direct) == len(graph) == 1
    assert recorder.exports == 0
    assert list(direct) == list(graph) == [SymbolId("m.f")]
    assert direct[SymbolId("m.f")] == state.summaries[SymbolId("m.f")]
    assert graph[SymbolId("m.f")] == ()
    assert recorder.exports == 2
    assert graph[SymbolId("m.f")] == ()
    assert recorder.exports == 2
    build_native_function_summary_state(context, state, frozenset({ModuleId("m")}))
    assert recorder.changed == ["m"]


@pytest.mark.parametrize("effect", list(Effect))
@pytest.mark.parametrize("access", list(AccessPath))
def test_native_effect_contract_round_trip(effect: Effect, access: AccessPath) -> None:
    context = make_context(
        analyze(make_source("m.py", "from vendor import send\ndef f(): send()\n")),
        extra_catalog_entries=(CatalogEntry(SymbolId("vendor.send"), frozenset({effect}), access),),
    )
    summary = context.function_summaries[SymbolId("m.f")]
    assert decode_summary(encode_summary(summary)) == summary
