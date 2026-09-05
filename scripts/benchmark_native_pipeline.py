"""Compare explicit Python/native hosts in balanced order on disposable source snapshots."""

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
from typing import cast

from taut.check_service import CheckRequest, ResidentCheckSession
from taut.policy.native_function_summaries import SummaryBackend


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def worker(snapshot: Path, output: Path, backend: SummaryBackend) -> None:
    samples: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="taut-pipeline-") as temporary:
        root = Path(temporary) / "project"
        shutil.copytree(
            snapshot,
            root,
            ignore=shutil.ignore_patterns(
                ".git", ".venv", "__pycache__", ".taut_cache", ".taut-cache"
            ),
        )
        os.environ["TAUT_RUNTIME_DIR"] = str(Path(temporary) / "runtime")
        with ResidentCheckSession(root, summary_backend=backend) as session:
            for phase, relative, count in (
                ("first", None, 1),
                ("ordinary", "alembic/env.py", 5),
                ("shared", "app/core/config.py", 5),
            ):
                path = root / relative if relative else None
                original = path.read_text() if path else ""
                for index in range(count):
                    if path:
                        path.write_text(original + f"\n# native-pipeline-{index}\n")
                    started = time.perf_counter()
                    result = session.check(CheckRequest(root))
                    elapsed = time.perf_counter() - started
                    samples.append(
                        dict(
                            phase=phase,
                            seconds=elapsed,
                            stages_ms={t.name: t.milliseconds for t in result.timings},
                            native_phase_seconds=session.summary_timings,
                            stdout_sha256=digest(result.stdout),
                            stderr_sha256=digest(result.stderr),
                            exit_code=result.exit_code,
                        )
                    )
                if path:
                    path.write_text(original)
                    session.check(CheckRequest(root))
    output.write_text(json.dumps(dict(backend=backend, samples=samples), indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--baseline-python", type=Path)
    parser.add_argument("--worker", choices=("python", "rust"))
    args = parser.parse_args()
    snapshot, output = Path(args.snapshot).resolve(), Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.worker:
        worker(snapshot, output, cast(SummaryBackend, args.worker))
        return
    if args.baseline_python is None:
        parser.error("--baseline-python is required for comparison")
    manifests = {
        str(p.relative_to(snapshot)): digest(p.read_bytes())
        for p in sorted(snapshot.rglob("*"))
        if p.is_file()
    }
    executions: list[dict[str, object]] = []
    orders = [("python", "rust_v1", "rust_v2"), ("rust_v2", "rust_v1", "python")]
    medians: dict[str, dict[str, list[float]]] = {
        label: {phase: [] for phase in ("first", "ordinary", "shared")} for label in orders[0]
    }
    for round_index, order in enumerate(orders):
        for label in order:
            interpreter = str(args.baseline_python) if label == "rust_v1" else sys.executable
            part = output.with_suffix(f".{round_index}.{label}.json")
            subprocess.run(
                [
                    interpreter,
                    __file__,
                    str(snapshot),
                    str(part),
                    "--worker",
                    "python" if label == "python" else "rust",
                ],
                check=True,
            )
            data = json.loads(part.read_text())
            executions.append(dict(round=round_index, label=label, result=data))
            for row in data["samples"]:
                medians[label][row["phase"]].append(row["seconds"])
            print(
                round_index,
                label,
                {
                    phase: round(statistics.median(values), 3)
                    for phase, values in medians[label].items()
                },
                flush=True,
            )
    assert all(digest((snapshot / path).read_bytes()) == value for path, value in manifests.items())
    output.write_text(
        json.dumps(
            dict(
                order=orders,
                executions=executions,
                medians_seconds={
                    label: {phase: statistics.median(values) for phase, values in phases.items()}
                    for label, phases in medians.items()
                },
                snapshot_preserved=True,
                source_files=sum(path.endswith(".py") for path in manifests),
            ),
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
