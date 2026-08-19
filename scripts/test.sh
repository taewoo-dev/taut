#!/bin/bash
# taut local/CI verification entrypoint.

set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ONLY_TARGET=""
SKIP_STATIC=false
SKIP_BUILD=false
PYTEST_EXTRA_ARGS=()
BUILD_DIR=""

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  GREEN='\033[0;32m'
  RED='\033[0;31m'
  BLUE='\033[0;34m'
  NC='\033[0m'
else
  GREEN=''
  RED=''
  BLUE=''
  NC=''
fi

usage() {
  cat <<'EOF'
Usage: bash scripts/test.sh [OPTIONS]

Options:
  --skip-static     Skip convention, format, lint, and type checks
  --skip-build      Skip wheel build and isolated import smoke
  --only <target>   Run one pytest path or node; pass remaining args to pytest
  -h, --help        Show this help
EOF
}

fail() {
  printf '%bERROR: %s%b\n' "$RED" "$1" "$NC" >&2
  exit 1
}

section() {
  printf '\n%b[%s]%b %s\n' "$BLUE" "$1" "$NC" "$2"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-static)
      SKIP_STATIC=true
      shift
      ;;
    --skip-build)
      SKIP_BUILD=true
      shift
      ;;
    --only)
      [[ $# -ge 2 ]] || fail "--only requires a pytest path or node id"
      ONLY_TARGET="$2"
      shift 2
      PYTEST_EXTRA_ARGS=("$@")
      break
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

cleanup() {
  local status=$?
  if [[ -n "$BUILD_DIR" && -d "$BUILD_DIR" ]]; then
    rm -r -- "$BUILD_DIR"
  fi
  return "$status"
}
trap cleanup EXIT

command -v uv >/dev/null 2>&1 || fail "uv is required"
cd "$PROJECT_ROOT"

section "1/5" "Synchronizing locked dependencies"
uv sync --locked

if [[ -n "$ONLY_TARGET" ]]; then
  section "TEST" "Running selected pytest target: $ONLY_TARGET"
  uv run --locked pytest "$ONLY_TARGET" ${PYTEST_EXTRA_ARGS[@]+"${PYTEST_EXTRA_ARGS[@]}"}
  printf '\n%bSelected test passed%b\n' "$GREEN" "$NC"
  exit 0
fi

if [[ "$SKIP_STATIC" == false ]]; then
  section "2/5" "Checking conventions, formatting, lint, and types"
  uv run --locked python scripts/check_conventions.py
  uv run --locked ruff format --check src tests scripts
  uv run --locked ruff check src tests scripts
  uv run --locked mypy
  uv run --locked pyright
  uv run --locked taut check .
else
  section "2/5" "Skipping static checks (--skip-static)"
fi

section "3/5" "Running tests with branch coverage"
uv run --locked pytest \
  --cov=taut \
  --cov-branch \
  --cov-report=term-missing \
  --cov-fail-under=90

if [[ "$SKIP_BUILD" == false ]]; then
  section "4/5" "Building wheel and source archive"
  BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/taut-dist.XXXXXX")"
  uv build --out-dir "$BUILD_DIR" --clear

  section "5/5" "Installing wheel in isolation"
  WHEELS=("$BUILD_DIR"/*.whl)
  [[ -e "${WHEELS[0]}" ]] || fail "uv build did not produce a wheel"
  uv run --isolated --no-project --with "${WHEELS[0]}" -- \
    python -c "import taut; from taut.cli import main; print(taut.__version__)"
else
  section "4-5/5" "Skipping build verification (--skip-build)"
fi

printf '\n%bAll checks passed%b\n' "$GREEN" "$NC"
