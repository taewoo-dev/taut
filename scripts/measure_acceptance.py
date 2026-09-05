"""Run one engine's acceptance measurements in a disposable real-project copy.

Use PYTHONPATH to select a baseline archive; run versions sequentially. This script
never imports or executes target application code. JSON results include all samples.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import taut
from taut.check_service import CheckRequest
from taut.daemon_client import check_daemon, daemon_status, stop_daemon


def rss(pid: int) -> int:
    output = subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)], text=True)
    return int(output.strip()) * 1024


def oracle(project: Path, *, json_output: bool = False) -> tuple[bytes, bytes, int]:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "taut.cli",
            "check",
            str(project),
            "--no-cache",
            "--daemon",
            "never",
            "--color",
            "never",
            "--width",
            "100",
            *(["--format", "json"] if json_output else []),
        ],
        capture_output=True,
        check=False,
    )
    return result.stdout, result.stderr, result.returncode


def summarize(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    return {
        "median": statistics.median(ordered),
        "p95": ordered[max(0, (95 * len(ordered) + 99) // 100 - 1)],
        "max": max(ordered),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--repeats", type=int, default=20)
    parser.add_argument("--cold-repeats", type=int, default=5)
    parser.add_argument("--memory-checks", type=int, default=200)
    parser.add_argument("--mixed-checks", type=int, default=100)
    parser.add_argument("--probe-checks", type=int, default=30)
    args = parser.parse_args()
    if (
        min(
            args.repeats,
            args.cold_repeats,
            args.memory_checks,
            args.mixed_checks,
            args.probe_checks,
        )
        < 1
    ):
        parser.error("all counts must be positive")
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="taut-acceptance-") as temporary:
        project = Path(temporary) / "project"
        shutil.copytree(
            args.snapshot,
            project,
            ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", ".taut-cache"),
        )
        os.environ["TAUT_RUNTIME_DIR"] = str(Path(temporary) / "runtime")
        paths = {"ordinary": project / "alembic/env.py", "shared": project / "app/core/config.py"}
        seeds: dict[str, str] = {}
        for phase, path in paths.items():
            seeds[phase] = path.read_text().rstrip() + f"\n# taut-acceptance-{phase}=00000000\n"
            path.write_text(seeds[phase])
        expected = oracle(project)
        assert expected[2] == 0
        request = CheckRequest(project, width=100)
        rows: dict[str, list[float]] = {}
        memory: dict[str, list[int]] = {"unchanged": [], "mixed": []}
        probes: list[dict[str, object]] = []
        completed = False
        stopped = False
        source_digest = hashlib.sha256()
        package = Path(taut.__file__).resolve().parent
        for source_file in sorted(package.rglob("*.py")):
            source_digest.update(
                str(source_file.relative_to(package)).encode()
                + b"\0"
                + source_file.read_bytes()
                + b"\0"
            )

        def save() -> None:
            output.write_text(
                json.dumps(
                    {
                        "harness_version": 2,
                        "mixed_edit_mode": "semantic-cycle/json-oracle",
                        "completed": completed,
                        "daemon_stopped": stopped,
                        "engine_source_sha256": source_digest.hexdigest(),
                        "samples_seconds": rows,
                        "summary_seconds": {
                            name: summarize(values) for name, values in rows.items()
                        },
                        "rss_bytes": memory,
                        "probes": probes,
                        "oracle_stdout_sha256": hashlib.sha256(expected[0]).hexdigest(),
                    },
                    indent=2,
                )
                + "\n"
            )

        def check(phase: str) -> None:
            started = time.perf_counter()
            result = check_daemon(request)
            seconds = time.perf_counter() - started
            assert (result.stdout, result.stderr, result.exit_code) == expected, phase
            rows.setdefault(phase, []).append(seconds)

        probe = project / "app/services/taut_acceptance_probe.py"
        cases = [
            ("safe", "value = 1\n", 0),
            ("lambda", "import time\nasync def run():\n    (lambda: time.sleep(1))()\n", 1),
            (
                "callback",
                "import time\ndef invoke(fn):\n    fn(1)\n"
                "async def run():\n    invoke(time.sleep)\n",
                1,
            ),
            (
                "offload",
                "import asyncio\nimport time\nasync def run():\n"
                "    await asyncio.to_thread(time.sleep, 1)\n",
                0,
            ),
            ("remove", None, 0),
        ]
        probe_request = CheckRequest(project, output_format="json", width=100)
        probe_oracles: dict[str, tuple[bytes, bytes, int]] = {}

        def probe_check(index: int, *, fresh_each: bool, phase: str) -> tuple[str, int]:
            name, source, code = cases[index % len(cases)]
            if source is None:
                probe.unlink(missing_ok=True)
            else:
                probe.write_text(source)
            started = time.perf_counter()
            result = check_daemon(probe_request)
            rows.setdefault(phase, []).append(time.perf_counter() - started)
            if fresh_each or name not in probe_oracles:
                probe_oracles[name] = oracle(project, json_output=True)
            assert (result.stdout, result.stderr, result.exit_code) == probe_oracles[name]
            assert result.exit_code == code
            return name, code

        try:
            for _ in range(args.cold_repeats):
                stop_daemon(project)
                check("cold")
                save()
            for phase in ("ordinary", "shared"):
                for index in range(args.repeats):
                    paths[phase].write_text(seeds[phase].replace("=00000000", f"={index + 1:08d}"))
                    check(phase)
                save()
                print(phase, summarize(rows[phase]), flush=True)
            for kind, count in (("unchanged", args.memory_checks), ("mixed", args.mixed_checks)):
                for index in range(count):
                    if kind == "mixed":
                        probe_check(index, fresh_each=False, phase="mixed")
                    else:
                        check(kind)
                    status = daemon_status(project)
                    assert status is not None
                    memory[kind].append(rss(status.pid))
                    if index % 25 == 0:
                        save()
                        print(
                            kind,
                            index + 1,
                            "rss_mib",
                            round(memory[kind][-1] / 1048576, 1),
                            flush=True,
                        )
                save()
            for index in range(args.probe_checks):
                name, code = probe_check(index, fresh_each=True, phase="probe")
                probes.append({"case": name, "exit": code, "fresh_parity": True})
                save()
                print("probe", index + 1, name, "parity", True, flush=True)
            completed = True
        finally:
            stopped = stop_daemon(project)
            save()
            print("daemon_stopped", stopped, flush=True)


if __name__ == "__main__":
    main()
