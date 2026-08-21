# Performance contract

`scripts/benchmark_performance.py` has two explicit modes:

* Synthetic scaling (`--scale small|medium|large`) generates deterministic
  generic Python or mixed FastAPI + SQLAlchemy + Pydantic projects at 8, 32,
  and 96 modules. These results are labeled `mode: synthetic`; they are not
  anti-monitor evidence.
* Real checkout (`--real-checkout PATH --requested N`) reads Python files from
  the named checkout only. It reports `requested`, `discovered`, `complete`,
  `partial`, `failed`, `status`, wall time, normalized RSS bytes, throughput,
  snapshot digest, analysis issues, and actual `PolicyRunResult.engine_issues`.
  It never writes files or starts a watcher; `files_read` makes the read scope
  auditable, and the command has no watcher implementation.

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
```

The real checkout command is the path for the exact anti-monitor validation;
synthetic 952-source experiments must not be labeled as that evidence. A
successful 952/952 result has `requested=952`, `discovered=952`,
`complete=952`, `partial=0`, `failed=0`, and `status=complete`.

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
