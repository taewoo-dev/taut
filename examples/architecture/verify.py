# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "pytaut==0.10.0",
#   "fastapi==0.116.1",
#   "httpx==0.28.1",
#   "ruff==0.12.12",
#   "mypy==1.18.2",
#   "pyright==1.1.405",
# ]
# ///
"""Verify the hand-authored demo against released tools, without editing its sources."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import subprocess
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOOLS = ("pytaut", "fastapi", "httpx", "ruff", "mypy", "pyright")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="Write the actual command results as JSON.")
    args = parser.parse_args()
    results: list[dict[str, object]] = []
    verified = False
    policy_digest = hashlib.sha256((ROOT / "policy.toml").read_bytes()).hexdigest()

    def run(variant: str, command: list[str], expected: int = 0) -> str:
        display_command = ["python" if part == sys.executable else part for part in command]
        print(f"\n[{variant}] $ {' '.join(display_command)}", flush=True)
        completed = subprocess.run(
            command,
            cwd=ROOT / variant,
            text=True,
            capture_output=True,
            timeout=180,
            env={**os.environ, "NO_COLOR": "1", "PYTHONPATH": str(ROOT / variant)},
        )
        output = (completed.stdout + completed.stderr).replace(str(ROOT), "examples/architecture")
        if "--format" not in command:
            print(output, end="" if output.endswith("\n") else "\n", flush=True)
        else:
            print("Structured report captured.", flush=True)
        print(f"exit {completed.returncode} (expected {expected})", flush=True)
        results.append(
            {
                "variant": variant,
                "command": display_command,
                "expected_exit": expected,
                "actual_exit": completed.returncode,
                "output": output,
            }
        )
        if completed.returncode != expected:
            raise RuntimeError(f"Unexpected exit code for {variant}: {command}")
        return completed.stdout

    try:
        for variant in ("before", "after"):
            config = tomllib.loads((ROOT / variant / "pyproject.toml").read_text())
            if config["tool"]["taut"] != {"extend": "../policy.toml"}:
                raise RuntimeError("Both variants must use the same policy without overrides")
        for name in ("main.py", "service.py", "repository.py"):
            if (ROOT / "before/app" / name).read_bytes() != (
                ROOT / "after/app" / name
            ).read_bytes():
                raise RuntimeError(f"Only router.py should change, but {name} differs")
        before = (ROOT / "before/app/router.py").read_text()
        after = (ROOT / "after/app/router.py").read_text()
        if (
            before.replace(
                "from app.repository import read_greeting as get_greeting",
                "from app.service import get_greeting",
            )
            != after
        ):
            raise RuntimeError("The demo must change exactly one import")
        for variant in ("before", "after"):
            run(
                variant,
                [
                    "ruff",
                    "check",
                    "--isolated",
                    "--select",
                    "E,F,I,UP,B",
                    "--target-version",
                    "py312",
                    "app",
                ],
            )
            run(
                variant,
                [
                    "mypy",
                    "--strict",
                    "--explicit-package-bases",
                    "--no-incremental",
                    "--cache-dir",
                    os.devnull,
                    "app",
                ],
            )
            run(variant, ["pyright", "--pythonversion", "3.12", "app"])
            run(
                variant,
                [
                    sys.executable,
                    "-c",
                    "from fastapi.testclient import TestClient; from app.main import app; "
                    "response = TestClient(app).get('/greetings/'); "
                    "assert response.status_code == 200; "
                    "assert response.json() == 'Hello from the repository'; "
                    "print('GET /greetings/: 200, expected response')",
                ],
            )
            run(variant, ["taut", "config", "validate", "."])
            run(variant, ["taut", "audit", "."])
            expected = 1 if variant == "before" else 0
            run(variant, ["taut", "check", ".", "--no-cache"], expected)
            report = json.loads(
                run(variant, ["taut", "check", ".", "--no-cache", "--format", "json"], expected)
            )
            # Compare the public diagnostic contract, not just a failing exit code.
            errors = [item for item in report["diagnostics"] if item["level"] == "enforced"]
            if [item["rule_id"] for item in errors] != (["ARCH001"] if variant == "before" else []):
                raise RuntimeError(f"Unexpected diagnostics in {variant}")
            if (
                not report["assurance"]["complete"]
                or report["engine_issues"]
                or report["coverage"]["gaps"]
                or report["coverage"]["indeterminate"]
            ):
                raise RuntimeError(f"Incomplete analysis in {variant}")
        if hashlib.sha256((ROOT / "policy.toml").read_bytes()).hexdigest() != policy_digest:
            raise RuntimeError("The shared policy changed during verification")
        verified = True
    finally:
        if args.report:
            payload = {
                "recorded_at": datetime.now(UTC).isoformat(),
                "verified": verified,
                "python": sys.version.split()[0],
                "versions": {name: importlib.metadata.version(name) for name in TOOLS},
                "provenance": (
                    "Hand-authored example; real CLI and HTTP results; not an AI session."
                ),
                "shared_policy_sha256": policy_digest,
                "sources": {
                    str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in sorted(ROOT.glob("*/app/*.py"))
                    + sorted(ROOT.glob("*/pyproject.toml"))
                },
                "commands": results,
            }
            args.report.write_text(json.dumps(payload, indent=2) + "\n")
    print("\nVerified: both apps run; only the forbidden import fails Taut; policy unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
