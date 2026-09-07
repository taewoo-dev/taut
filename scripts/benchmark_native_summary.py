"""Sequential, isolated optional native backend measurements; target code is never executed."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import cast

from taut.check_service import CheckRequest, CheckResult, ResidentCheckSession, run_check_request
from taut.domain.ids import SymbolId
from taut.policy.function_summaries import strongly_connected_components
from taut.policy.native_function_summaries import NativeRow, SummaryBackend, native_factory
from taut.reporting.json import render_json


def rss() -> int:
    return int(subprocess.check_output(["ps", "-o", "rss=", "-p", str(os.getpid())])) * 1024


def stable(samples: list[int]) -> bool:
    tolerance = max(8 << 20, int(samples[0] * 0.03))
    tail = samples[len(samples) // 2 :]
    return samples[-1] - samples[0] <= tolerance and max(tail) - min(tail) <= tolerance


def same(left: CheckResult, right: CheckResult) -> None:
    assert (left.stdout, left.stderr, left.exit_code, left.report) == (
        right.stdout,
        right.stderr,
        right.exit_code,
        right.report,
    )


def synthetic(output: Path) -> None:
    results: list[dict[str, object]] = []
    for size in (1000, 10000, 100000):
        for shape in ("chain", "shared", "cycle"):
            names = [f"m.f{i:06}" for i in range(size)]
            rows: list[NativeRow] = []
            for i, name in enumerate(names):
                targets = (
                    [names[(i + 1) % size]]
                    if shape == "cycle"
                    else [names[i + 1]]
                    if shape == "chain" and i + 1 < size
                    else [names[-1]]
                    if shape == "shared" and i + 1 < size
                    else []
                )
                rows.append(
                    (
                        name,
                        "m",
                        targets,
                        (1 if i == size - 1 else 0, 1 if i == size - 1 else 0, [], [], 0),
                    )
                )
            started = time.perf_counter()
            graph = {SymbolId(n): frozenset(SymbolId(c) for c in calls) for n, _, calls, _ in rows}
            components = strongly_connected_components(graph)
            owners = {n: i for i, comp in enumerate(components) for n in comp}
            outgoing: list[set[int]] = [set() for _ in components]
            reverse: list[set[int]] = [set() for _ in components]
            for n, calls in graph.items():
                for c in calls:
                    if owners[n] != owners[c]:
                        outgoing[owners[n]].add(owners[c])
                        reverse[owners[c]].add(owners[n])
            values = [int(SymbolId(names[-1]) in comp) for comp in components]
            remaining = [len(c) for c in outgoing]
            pending = [i for i, count in enumerate(remaining) if count == 0]
            while pending:
                i = pending.pop()
                for j in reverse[i]:
                    values[j] |= values[i]
                    remaining[j] -= 1
                    if remaining[j] == 0:
                        pending.append(j)
            python_seconds = time.perf_counter() - started
            started = time.perf_counter()
            state = native_factory().build(rows)
            exports = state.export()
            native_seconds = time.perf_counter() - started
            assert all(value[0] == values[owners[SymbolId(n)]] for n, value in exports)
            results.append(
                dict(
                    size=size,
                    shape=shape,
                    python_mask_reference_seconds=python_seconds,
                    native_with_conversion_seconds=native_seconds,
                    rust_compute_seconds=state.compute_seconds,
                    stats=state.stats(),
                )
            )
            print(size, shape, python_seconds, native_seconds, flush=True)
    output.write_text(json.dumps(results, indent=2) + "\n")


def real(snapshot: Path, output: Path, backend: SummaryBackend, quick: bool) -> None:
    counts = (1, 2, 5, 3, 5, 5) if quick else (5, 20, 200, 100, 50, 30)
    cold_count, edit_count, unchanged_count, mixed_count, warm_count, probe_count = counts
    # Fresh reference comparison is required for the Rust candidate, not for itself.
    if backend == "python":
        probe_count = 0
    counts = (cold_count, edit_count, unchanged_count, mixed_count, warm_count, probe_count)
    data: dict[str, object] = dict(
        backend=backend,
        python=sys.version,
        platform=platform.platform(),
        baseline="598ad71",
        counts=counts,
    )
    cold: list[float] = []
    edits: dict[str, list[float]] = {"ordinary": [], "shared": []}
    phases: dict[str, list[tuple[float, ...]]] = {"cold": [], "ordinary": [], "shared": []}
    memory: dict[str, list[int]] = {"unchanged": [], "mixed": []}
    data.update(
        cold_seconds=cold, edit_seconds=edits, native_phase_seconds=phases, rss_bytes=memory
    )
    with tempfile.TemporaryDirectory(prefix="taut-native-") as temporary:
        project = Path(temporary) / "project"
        shutil.copytree(
            snapshot,
            project,
            ignore=shutil.ignore_patterns(
                ".git", ".venv", "__pycache__", ".taut-cache", ".taut_cache"
            ),
        )
        os.environ["TAUT_RUNTIME_DIR"] = str(Path(temporary) / "runtime")
        request = CheckRequest(project)
        for i in range(cold_count):
            with ResidentCheckSession(project, summary_backend=backend) as session:
                started = time.perf_counter()
                session.check(request)
                cold.append(time.perf_counter() - started)
                phases["cold"].append(session.summary_timings)
            print(backend, "cold", i + 1, cold[-1], flush=True)
        with ResidentCheckSession(project, summary_backend=backend) as session:
            session.check(request)
            for kind, relative in (
                ("ordinary", "alembic/env.py"),
                ("shared", "app/core/config.py"),
            ):
                path = project / relative
                original = path.read_text()
                for i in range(edit_count):
                    path.write_text(original + f"\n# native-poc-{i}\n")
                    started = time.perf_counter()
                    session.check(request)
                    edits[kind].append(time.perf_counter() - started)
                    phases[kind].append(session.summary_timings)
                path.write_text(original)
                session.check(request)
                print(backend, kind, "done", flush=True)
            probe = project / "app/services/taut_native_probe.py"
            cases = [
                "async def run(): return 1\n",
                "import time\nasync def run(): (lambda: time.sleep(1))()\n",
                "import time\ndef helper(cb): cb()\n"
                "async def run(): helper(lambda: time.sleep(1))\n",
                "import asyncio, time\nasync def run(): await asyncio.to_thread(time.sleep, 1)\n",
                None,
            ]

            def update(i: int) -> None:
                source = cases[i % len(cases)]
                if source is None:
                    probe.unlink(missing_ok=True)
                else:
                    probe.write_text(source)

            for i in range(warm_count):
                update(i)
                session.check(request)
            for kind, count in (("unchanged", unchanged_count), ("mixed", mixed_count)):
                for i in range(count):
                    if kind == "mixed":
                        update(i)
                    session.check(request)
                    memory[kind].append(rss())
                    if (i + 1) % 20 == 0:
                        print(backend, kind, i + 1, flush=True)
            data["native_owned_counts"] = session.summary_statistics
            data["stable"] = {kind: stable(values) for kind, values in memory.items()}
            parity: list[int] = []
            for i in range(probe_count):
                update(i)
                expected = run_check_request(request)
                same(session.check(request), expected)
                json_result = session.check(CheckRequest(project, output_format="json"))
                assert expected.report is not None
                assert json_result.stdout == (render_json(expected.report) + "\n").encode()
                assert json_result.stderr == expected.stderr
                assert json_result.exit_code == expected.exit_code
                parity.append(i)
                print(backend, "probe", i + 1, flush=True)
            data["fresh_parity_probes"] = parity
    output.write_text(json.dumps(data, indent=2) + "\n")


def manifest(snapshot: Path) -> dict[str, str]:
    return {
        str(p.relative_to(snapshot)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(snapshot.rglob("*"))
        if p.is_file()
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--backend", choices=("python", "rust"))
    parser.add_argument("--synthetic", action="store_true")
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.synthetic:
        synthetic(output)
    elif args.backend:
        real(Path(args.snapshot), output, cast(SummaryBackend, args.backend), bool(args.quick))
    else:
        if args.snapshot is None:
            parser.error("--snapshot is required")
        snapshot = Path(args.snapshot).resolve()
        before = manifest(snapshot)
        for backend in ("python", "rust"):
            subprocess.run(
                [
                    sys.executable,
                    __file__,
                    str(output.with_suffix(f".{backend}.json")),
                    "--snapshot",
                    str(snapshot),
                    "--backend",
                    backend,
                    *(["--quick"] if args.quick else []),
                ],
                check=True,
            )
        assert manifest(snapshot) == before
        output.write_text(
            json.dumps(dict(snapshot=str(snapshot), manifest=before, preserved=True), indent=2)
            + "\n"
        )


if __name__ == "__main__":
    main()
