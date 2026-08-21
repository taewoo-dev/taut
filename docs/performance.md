# Performance contract

pytaut 0.2.0 has a deterministic, in-memory benchmark at
`scripts/benchmark_performance.py`. It generates generic Python and mixed
FastAPI + SQLAlchemy + Pydantic projects at 8 (small), 32 (medium), and 96
(large) modules. The benchmark records cold and warm wall time, peak-RSS delta,
source throughput, module count, engine issues, and the snapshot digest. It
does not read or write a project checkout and does not start a watcher, so it is
also the anti-monitor baseline.

Run it with:

```sh
uv run python scripts/benchmark_performance.py --scale all --repeats 2
uv run python scripts/benchmark_performance.py --generic --scale medium
uv run python scripts/benchmark_performance.py --scale small --anti-monitor
```

The JSON output includes Python/platform/processor metadata. Treat timing and
RSS as measurements, not exact golden values: CI regression checks should use
the median of at least three runs and fail only when the median exceeds a
baseline by 2x (wall time) or 3x (RSS), with a 0.05-second minimum wall-time
floor to avoid timer noise. The deterministic contract is stricter: every
repeat at every scale must have the same digest, module count, and zero engine
issues.

The provider contract is one invocation per provider per snapshot. Providers
may inspect the immutable snapshot, but rules consume their capabilities and
must not trigger provider analysis again. `PolicyEngine` caches scheduler
targets by `(target kind, zones)` so rules sharing a target set do not rescan
modules to rebuild identical targets.

Existing representative coverage is under `tests/fixtures/providers/fastapi`
and `tests/fixtures/providers/sqlalchemy`; the generated mixed fixture extends
that shape without depending on external repositories. Generic behavior is
covered by the same harness with `--generic`.

## Baseline recording

Store benchmark JSON as a CI artifact or attach it to a release review. Do not
commit machine-specific timings as source truth. A performance change is
acceptable only when the digest/results contract remains unchanged and the
anti-monitor flags remain false. `scripts/test.sh` remains the authoritative
full test/static/build verification entrypoint.
