# Performance contract

`scripts/benchmark_performance.py` has three explicit modes:

* Synthetic scaling (`--scale small|medium|large`) generates deterministic
  generic Python or mixed FastAPI + SQLAlchemy + Pydantic projects at 8, 32,
  and 96 modules. These results are labeled `mode: synthetic`; they are not
  measurements of a real checkout.
* Real checkout (`--real-checkout PATH --requested N`) reads Python files from
  the named checkout only. It reports `requested`, `discovered`, `complete`,
  `partial`, `failed`, `status`, wall time, normalized RSS bytes, throughput,
  snapshot digest, analysis issues, and actual `PolicyRunResult.engine_issues`.
  It never writes files or starts a watcher; `files_read` makes the read scope
  auditable, and the command has no watcher implementation.
* Resident daemon (`--daemon-benchmark PATH`) stages discovered sources and the
  active configuration into a temporary project. It compares every daemon result
  byte-for-byte with `--daemon never`, applies a distinct fixed-width comment edit
  before every ordinary/shared sample, records invalidation counters, exercises
  restart and concurrent clients, and samples the daemon process RSS.

Synthetic benchmark repeats are independent runs. There is no warm-cache claim:
each repeat constructs a fresh adapter/analyzer and executes analysis, all
built-in providers, and the real `PolicyEngine`. Every repeat must preserve the
same snapshot digest, module count, and zero analysis/engine issues.

RSS uses `resource.getrusage().ru_maxrss`, normalized to bytes (`bytes` on
macOS, `KiB * 1024` on Linux). Measurements expose `rss_bytes`, not a
platform-dependent `rss_kib` value.

```sh
uv run python scripts/benchmark_performance.py --scale all --repeats 3
uv run python scripts/benchmark_performance.py --generic --scale medium
uv run python scripts/benchmark_performance.py \
  --real-checkout /path/to/checkout --requested 952 --scale small
uv run python scripts/benchmark_performance.py --scale small --repeats 1 \
  --daemon-benchmark /path/to/checkout \
  --daemon-timing-repeats 5 --daemon-memory-checks 30
```

Set `--requested` to the expected source count of your checkout. A complete result
has matching requested, discovered, and complete counts, with zero partial/failed
sources and `status=complete`. Do not present synthetic runs as real-project evidence.

## Cache and daemon correctness

Both acceleration modes must preserve stdout, stderr, and exit-code parity with
canonical analysis. See [operations](operations.md) for commands and lifecycle.

The fast bundle is an optimization, not a source of truth. Missing keys, invalid
signatures, incompatible interpreters, malformed payloads, disallowed types, and
I/O failures become cache misses and fall back to canonical analysis.

The daemon benchmark selects ordinary and shared sources by transitive inbound
impact. Interpret edit timings alongside reparsed modules, reused evaluations,
source count, machine details, and memory samples. Measure your own workload;
no universal latency or memory bound is promised.

## Baseline enforcement

The JSON schema is `pytaut-performance-baseline-v1`. Save one benchmark JSON
artifact, then compare a later run with:

```sh
uv run python scripts/benchmark_performance.py \
  --scale all --repeats 3 --baseline baseline.json
```

Comparison uses the median of repeats and returns exit code 1 if wall time is
over 2x the baseline (with a 0.05-second floor) or RSS is over 3x (with a
1-MiB floor). The comparison payload lists each scale/metric violation, making
the contract enforceable in CI rather than advisory prose.

Existing checked-in representative fixtures remain under
`tests/fixtures/providers/fastapi` and `tests/fixtures/providers/sqlalchemy`;
the generated mixed fixture supplements them without touching external repos.
`scripts/test.sh` remains the full static/test/build verification entrypoint.
