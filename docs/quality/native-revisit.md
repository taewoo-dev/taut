# Callback forwarding and native revisit — 2026-09-05

The follow-up propagates known catalog callback effects through exact parameter forwarding
between undecorated synchronous helpers, including across modules. Monotone invocation sets
reach a fixed point, so source ordering and recursive forwarding do not require an arbitrary
depth cutoff. Guarded/context-managed paths retain uncertainty; storage, offloading, invalid
binding, and reassigned parameters do not establish a definite effect. Empty invocation entries
are discarded after propagation to avoid retaining unrelated functions in the callback index.

The full gate passed 1,363 tests at 90.42% coverage with branch measurement. Existing anti-monitor
source passed, while an injected multi-hop blocking callback produced ASYNC001 with exact
resident/fresh stdout, stderr, and exit parity. These injected cases do not demonstrate an
existing application bug. [Probe results](callback-forwarding.json).

## Current native boundary measurement

Use the same 1,224-source snapshot as the [preceding validation](antimonitor-followup.md).
Only temporary copies were modified. Three independent `ResidentCheckSession` lifetimes each
measured a first JSON check, an unchanged check, then a comment edit to `alembic/env.py`.
Restore the file between lifetimes. Collect `perf_counter` wall time and `CheckResult.timings`.
The existing four-worker analysis path was used; checks exited 0 with no engine issues.
Unchanged stdout/stderr/exit matched each session's first check. These timing samples do not
separately establish fresh parity for the comment edit; transitive-edit parity is covered by
the integration suite and the controlled real-project probes.

| Phase | Median wall time | Analysis fraction of total sampled wall | Gain if analysis were 3x faster | Infinite analysis speed limit |
|---|---:|---:|---:|---:|
| Cold | 12.390 s | 49.9% | 1.50x | 2.00x |
| Ordinary edit | 3.454 s | 20.9% | 1.16x | 1.26x |

Unchanged median was 0.405 s. Fractions use summed stage and wall durations across the three
runs, not a ratio of independently selected medians. For fraction `f` and kernel speedup `s`,
the estimated complete-run speedup is `1 / (1 - f + f / s)`.
[Raw samples, stages, source hashes, and bounds](native-revisit.json).

These are shared-machine observations, not a controlled before/after regression comparison.
The ordinary-edit sample is slower than the previous pilot and exceeds the 2-second goal;
do not interpret this change as a performance improvement. The analysis stage is an optimistic
proxy for a module-sized native kernel. No Rust code, serialization boundary, compilation,
wheel, or fallback was benchmarked. The bounds are hypotheses, not measured Rust speedups.

## Decision

Keep Rust as a measured option rather than begin a rewrite. A parser-only replacement would
address less work than the already optimistic analysis-stage bound. About 79% of ordinary-edit
wall time remains outside analysis, so even an infinitely fast analysis kernel cannot meet the
2-second ordinary-edit target from this sample. Profile and reduce policy/index rebuilding,
providers, reporting, discovery, and project assembly first; this stage measurement does not
identify their individual hot functions.

If cold latency becomes the binding requirement, a module-sized Rust kernel is still a plausible
experiment: the modeled 3x kernel gain is about 1.50x overall. Before implementation, specify
the cold-latency target, semantic ABI, batched input/output, boundary-cost budget, Python fallback,
and differential/fuzz validation. Retain the existing Phase 6 wheel and plugin-compatibility
requirements. General method/decorator callback dispatch and arbitrary higher-order callable
transformations remain separate correctness work, regardless of implementation language.
