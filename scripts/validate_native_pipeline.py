"""Measure resident memory, then compare native transaction edits against fresh Python."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import cast

from taut.check_service import CheckRequest, ResidentCheckSession, run_check_request
from taut.policy.native_function_summaries import SummaryBackend
from taut.reporting.json import render_json

_PREFIX = "from tortoise.models import Model\nclass NativeProbe(Model): pass\n"
_CASES = (
    "async def run(): return 1\n",
    _PREFIX + "async def run(): await NativeProbe.create()\n",
    _PREFIX + "async def run():\n    await NativeProbe.create()\n    await NativeProbe.create()\n",
    _PREFIX + "from tortoise.transactions import atomic\n@atomic()\n"
    "async def run():\n    await NativeProbe.create()\n    await NativeProbe.create()\n",
    _PREFIX + "from tortoise.transactions import in_transaction\nasync def run():\n"
    "    async with in_transaction():\n        await NativeProbe.create()\n"
    "        await NativeProbe.create()\n",
    "import time\ndef helper(callback): callback()\n"
    "async def run(): helper(lambda: time.sleep(0))\n",
    None,
)


def rss() -> int:
    return int(subprocess.check_output(["ps", "-o", "rss=", "-p", str(os.getpid())])) * 1024


def stable(values: list[int]) -> bool:
    tolerance = max(8 << 20, int(values[0] * 0.03))
    tail = values[len(values) // 2 :]
    return values[-1] - values[0] <= tolerance and max(tail) - min(tail) <= tolerance


def worker(snapshot: Path, output: Path, backend: SummaryBackend) -> None:
    samples: dict[str, list[int]] = {"unchanged": [], "mixed": []}
    parity: list[int] = []
    with tempfile.TemporaryDirectory(prefix="taut-native-validation-") as temporary:
        root = Path(temporary) / "project"
        shutil.copytree(
            snapshot,
            root,
            ignore=shutil.ignore_patterns(
                ".git", ".venv", "__pycache__", ".taut_cache", ".taut-cache"
            ),
        )
        os.environ["TAUT_RUNTIME_DIR"] = str(Path(temporary) / "runtime")
        probe = root / "app/services/taut_native_pipeline_probe.py"
        request = CheckRequest(root)

        def update(index: int) -> None:
            source = _CASES[index % len(_CASES)]
            if source is None:
                probe.unlink(missing_ok=True)
            else:
                probe.write_text(source)

        with ResidentCheckSession(root, summary_backend=backend) as session:
            for index in range(50):
                update(index)
                session.check(request)
            print(backend, "warmup complete", flush=True)
            for phase, count in (("unchanged", 100), ("mixed", 50)):
                for index in range(count):
                    if phase == "mixed":
                        update(index)
                    session.check(request)
                    samples[phase].append(rss())
                print(backend, phase, "complete", flush=True)
            if backend == "rust":
                for index in range(14):
                    update(index)
                    actual, expected = session.check(request), run_check_request(request)
                    assert (actual.report, actual.stdout, actual.stderr, actual.exit_code) == (
                        expected.report,
                        expected.stdout,
                        expected.stderr,
                        expected.exit_code,
                    )
                    assert expected.report is not None
                    actual_json = session.check(CheckRequest(root, output_format="json"))
                    assert actual_json.stdout == (render_json(expected.report) + "\n").encode()
                    assert actual_json.stderr == expected.stderr
                    assert actual_json.exit_code == expected.exit_code
                    parity.append(index)
                    print("fresh parity", index + 1, flush=True)
    output.write_text(
        json.dumps(
            dict(
                backend=backend,
                warmup=50,
                rss_bytes=samples,
                stable={phase: stable(values) for phase, values in samples.items()},
                fresh_parity=parity,
            ),
            indent=2,
        )
        + "\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--worker", choices=("python", "rust"))
    args = parser.parse_args()
    snapshot, output = Path(args.snapshot).resolve(), Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.worker:
        worker(snapshot, output, cast(SummaryBackend, args.worker))
        return
    for backend in ("python", "rust"):
        subprocess.run(
            [
                sys.executable,
                __file__,
                str(snapshot),
                str(output.with_suffix(f".{backend}.json")),
                "--worker",
                backend,
            ],
            check=True,
        )


if __name__ == "__main__":
    main()
