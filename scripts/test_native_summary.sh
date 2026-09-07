#!/bin/bash
# Opt-in local native gate. The default Python gate does not require Rust.
set -Eeuo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"
export PATH="$HOME/.cargo/bin:$PATH"
export PYO3_PYTHON="$PROJECT_ROOT/.venv/bin/python"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/taut-native-gate.XXXXXX")"
trap 'rm -r -- "$BUILD_DIR"' EXIT
cargo fmt --manifest-path native/summary_core/Cargo.toml -- --check
cargo clippy --locked --manifest-path native/summary_core/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path native/summary_core/Cargo.toml
uvx maturin==1.13.0 build --release --locked --manifest-path native/summary_core/Cargo.toml --out "$BUILD_DIR/native"
NATIVE_WHEELS=("$BUILD_DIR/native"/*.whl)
uv run --with "${NATIVE_WHEELS[0]}" pytest --cov=taut --cov-branch --cov-fail-under=90
uv build --out-dir "$BUILD_DIR/python"
PYTHON_WHEELS=("$BUILD_DIR/python"/*.whl)
uv run --isolated --no-project --with "${PYTHON_WHEELS[0]}" --with "${NATIVE_WHEELS[0]}" -- \
  python -c 'from pathlib import Path; from taut.check_service import CheckRequest, run_check_request; p = Path("tests/fixtures/installed_smoke").resolve(); a = run_check_request(CheckRequest(p)); b = run_check_request(CheckRequest(p), summary_backend="rust"); assert (a.report, a.stdout, a.stderr, a.exit_code) == (b.report, b.stdout, b.stderr, b.exit_code); print("installed native/Python report parity passed")'
