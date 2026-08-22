# Performance contract

`scripts/benchmark_performance.py` has three explicit modes:

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

The real checkout command is the path for the exact anti-monitor validation;
synthetic 952-source experiments must not be labeled as that evidence. A
successful 952/952 result has `requested=952`, `discovered=952`,
`complete=952`, `partial=0`, `failed=0`, and `status=complete`.

## 0.3.0 disk-cache contract

The project-local cache must preserve exact stdout, stderr, and exit-code parity
with `--no-cache`. The release thresholds on the anti-monitor validation checkout
are:

| Scenario | Limit | Observed |
|---|---:|---:|
| cold, no cache | 20 s | about 10.0 s |
| unchanged, disk cache | 3 s | about 0.2 s |
| ordinary one-file edit, disk cache | 8 s | 6.9–7.8 s |

The fast bundle is an optimization, not a source of truth. A missing key, invalid
signature, incompatible interpreter, malformed payload, disallowed type, or I/O
failure becomes a cache miss and falls back to canonical analysis.

## 0.4.0 resident-daemon contract

The daemon benchmark selects the ordinary source with the smallest transitive
inbound impact and the shared source with the largest. On the 952-module
anti-monitor checkout the selected files were `app/asgi.py` (0 transitive
importers) and `app/core/config.py` (610 transitive importers).

| Scenario | Limit | Final median |
|---|---:|---:|
| cold daemon | 20 s | 9.54 s |
| unchanged | 0.5 s | 0.189 s |
| ordinary edit | 2 s | 1.321 s |
| shared edit | 4 s | 2.723 s |

Every edit result reparsed exactly one module. The ordinary samples reused 217,446
of 218,018 policy evaluations; the shared samples reused 216,968. Across 30
unchanged memory checks, RSS moved from 769,130,496 to 744,325,120 bytes, with a
769,146,880-byte peak. The machine-readable release result is
[`performance/anti-monitor-0.4.0.json`](performance/anti-monitor-0.4.0.json).

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
