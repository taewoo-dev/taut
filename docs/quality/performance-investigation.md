# Performance test and bottleneck investigation — 2026-09-05

Tested engine commit `77dce3e` without changing engine code. `bash scripts/test.sh` passed
1,363 tests with 90.42% coverage including branch measurement, conventions, Ruff, strict
mypy/Pyright, strict self-policy, package builds, and installed-wheel smoke checks.

The real-project target remains the isolated 1,224-source anti-monitor snapshot identified in
[the earlier validation](antimonitor-followup.md). All edits were in disposable copies.
No original application files, configuration, or application/database state were changed.

## Unprofiled daemon test

Run the existing `scripts.benchmark_performance.daemon_benchmark(snapshot, timing_repeats=3,
memory_checks=30)`. It stages the project, chooses low/high dependency-impact files, and checks
every timed stdout/stderr/exit digest against a fresh CLI oracle. The run completed successfully,
including restart/concurrent checks, output parity, source preservation, and daemon cleanup.

| Phase | Median seconds | Maximum seconds |
|---|---:|---:|
| Cold, one observation | 11.708 | 11.708 |
| Unchanged | 0.349 | 0.353 |
| Ordinary edit | 1.858 | 3.065 |
| Shared edit | 4.735 | 4.936 |
| Restart | 12.266 | 12.360 |
| Concurrent clients | 0.933 | 1.445 |

The ordinary file was `alembic/env.py` (zero transitive inbound modules); the shared file was
`app/core/config.py` (650). Ordinary median met the previous 2-second goal in this sample, but
the maximum exceeded it; shared median exceeded the 4-second goal. The prior 3.454-second
ordinary result used a JSON resident API check and a different edit shape. These are shared-machine
observations with different harnesses, not evidence of a code speedup or a controlled regression.

Thirty unchanged memory checks met the existing plateau criterion: RSS before/after was about
820.5/813.9 MiB, peak 820.5 MiB, and tail span 3.8 MiB. This is short-run stability evidence.
It does not identify retained-object owners, establish a low memory requirement, or rule out leaks
under long edit sequences. Allocation/retention profiling remains separate work.

## Function profiles

For each edit independently, initialize `ResidentCheckSession` on another copy, perform a cold
JSON check, append a comment to the selected file, then wrap the next `session.check(request)`
with `cProfile.Profile`. Disable profiling before running `run_check_request(request)` as the
fresh oracle, and restore the edited file in `finally`. Both edited checks exited 0 with exact
stdout/stderr/exit parity. Profile timings include instrumentation and must not be compared
directly with the unprofiled daemon wall times above.

| Profile | Wall seconds | Analysis | Providers | Policy | Reporting |
|---|---:|---:|---:|---:|---:|
| Ordinary edit | 3.632 | 1.174 | 0.352 | 1.217 | 0.499 |
| Shared edit | 10.484 | 1.118 | 2.297 | 6.233 | 0.501 |

Discovery and small orchestration costs account for the remaining time. In both cases only one
module was reparsed and 1,223 were reused. Ordinary policy evaluations reused 236,856 and
recomputed 655; shared evaluations reused 149,318 and recomputed 88,193. Neither was a full
policy rerun. The provider counter reports five providers invoked; it does not mean all modules
inside each incremental provider were rebuilt.

The ordinary profile spends 1.142 seconds in `ProjectAnalyzer.assemble`, almost all of the
1.174-second analysis stage. Its nested project relation and index builders account for 0.569
and 0.478 seconds. Code inspection confirms they rebuild aggregate project indexes, sorted
relations, and coverage from the module results even when most module facts were reused.
Project-wide exception validation also costs 0.365 seconds, and assurance costs 0.491 seconds.

In the shared profile, policy execution dominates. Effect-uncertainty evaluation, async safety,
transaction checks, target scheduling, and function summaries are prominent nested costs.
Incremental FastAPI and SQLAlchemy providers take 0.945 and 0.911 seconds. These cumulative
function costs overlap; adding nested rows would double-count work. The aggregate retains top
cumulative/self costs and counters; full profiles stay in the temporary measurement directory.

## Concrete next improvements

1. Make project assembly reuse unchanged module contributions to indexes, relations, and
   coverage. Preserve deterministic ordering and verify add/remove/rename/import-resolution
   changes against a fresh oracle; do not skip global checks merely because only one file changed.
2. Refine provider and policy invalidation using the facts they consume, particularly for common
   configuration modules. The 88,193 recomputations quantify scope, not proof that they are all
   unnecessary. Establish semantic-change/dependency tests before narrowing invalidation.
3. Reuse per-module evidence for assurance and project-wide rules where merge semantics allow it.
4. Profile allocations and retained objects before choosing a memory representation change.

This gives a stronger reason to defer a parser-only Rust experiment: the measured ordinary
analysis cost is overwhelmingly project assembly, not reparsing. A broader Rust kernel remains
an option under the [native decision gate](native-revisit.md), but is not required to attempt the
incremental improvements above. No performance optimization was implemented in this test pass.

[Machine-readable results](performance-investigation.json).
