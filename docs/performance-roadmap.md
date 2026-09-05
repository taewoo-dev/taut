# Performance improvement roadmap

This document turns the performance research into an implementation sequence for
pytaut. The objective is not a benchmark-only speedup. Every optimization must
preserve deterministic findings, coverage, engine issues, exit codes, and rendered
output.

## Direction

Successful Python tools use several layers together:

- Ruff shares one parser and semantic model across first-party rules, caches
  unchanged files, and keeps its editor engine resident.
- uv avoids downloads, builds, and copies through dependency-aware caching and
  copy-on-write or hardlink installation.
- mypy combines module caches with a resident daemon and definition-level
  dependency tracking.
- Pyright keeps parse, bind, check, and diagnostic state per file and computes
  type information lazily.
- ty treats derived analysis as fine-grained incremental queries.

The relevant lesson for Taut is to eliminate repeated work before replacing the
implementation language. A native parser alone is not the current priority: local
profiling shows that Python-level fact extraction, flow merging, symbol matching,
and transitive summaries dominate parsing itself.

Primary references:

- [Ruff parser and end-to-end impact](https://astral.sh/blog/ruff-v0.4.0)
- [Ruff integrated language server](https://astral.sh/blog/ruff-v0.4.5)
- [uv cache semantics](https://docs.astral.sh/uv/concepts/cache/)
- [uv resolver internals](https://docs.astral.sh/uv/reference/internals/resolver/)
- [mypy daemon internals](https://github.com/python/mypy/wiki/Mypy-Daemon)
- [Pyright internals](https://github.com/microsoft/pyright/blob/main/docs/internals.md)
- [ty incremental architecture](https://astral.sh/blog/ty)

## Non-negotiable contracts

An optimization is complete only when all applicable contracts hold:

1. Fresh and optimized runs produce identical `RunReport` values.
2. Text and JSON stdout, stderr, and exit codes are byte-for-byte identical.
3. No analysis gap, indeterminate result, or engine issue is hidden to gain speed.
4. Cache/provider/adapter/config version changes invalidate incompatible state.
5. Add, remove, rename, syntax failure, and recovery match a fresh run.
6. Results remain deterministic across repeat runs and worker counts.
7. Resident memory reaches a stable plateau; latency improvement must not create
   unbounded retained state.
8. The pure canonical path remains available for CI and diagnosis.

Each phase begins with a failing performance or behavior test, lands independently,
and updates the checked-in benchmark evidence. A later phase must not be needed to
make an earlier phase correct.

## Measurement matrix

Every material change is evaluated against these scenarios:

| Scenario | Purpose | Required evidence |
|---|---|---|
| cold canonical | no prior process or cache reuse | wall, CPU, RSS, stage timings |
| warm disk cache | new process with reusable cache | parity, cache hits, wall |
| resident unchanged | no source/config change | zero recomputation, wall p50/p95 |
| leaf body edit | local implementation-only change | parsed modules, impacted definitions, wall p50/p95 |
| public signature edit | semantic interface change | exact reverse impact and parity |
| shared-module edit | high fan-out invalidation | bounded propagation, wall p50/p95 |
| add/remove/rename | graph topology change | fresh parity and exact counters |
| config/provider change | global semantic change | safe full invalidation |
| syntax failure/recovery | incomplete editor state | explicit issue and recovery parity |

Record the machine, OS, Python version, Taut version, source count, evaluation
count, diagnostic digest, and cache mode with every real-checkout result. Use at
least five timed repetitions for resident p50/p95 claims. Profilers may distort
this object-heavy workload, so use their call counts and topology; use unprofiled
runs for acceptance thresholds.

## Current reference point

Measured on 2026-09-05 on this Mac:

- pytaut: 0.7.0
- anti-monitor backend: 1,213 complete Python modules
- cold `--daemon never --no-cache`: 19.22 seconds wall, 32.92 seconds user,
  0.59 seconds system
- a forced single-worker run: 20.34 seconds total, including 12.78 seconds
  analysis, 1.29 seconds providers, 5.67 seconds policy, and 0.45 seconds reporting

The current checkout exits 1 because it contains policy diagnostics; that is not
an engine failure. Result parity, not exit zero, is the performance contract.

A nearby 1,208-file revision produced these resident measurements. They remain a
directional baseline and must not be represented as measurements of the current
1,213-file tree:

| Scenario | Median |
|---|---:|
| cold daemon | 17.515 s |
| unchanged | 0.399 s |
| ordinary one-file edit | 2.872 s |
| high-fan-out shared edit | 4.723 s |
| restart | 18.706 s |

Resident RSS was approximately 810 MiB and stable.

The single-worker profile recorded approximately 252 million Python calls. The
most important structural observations were:

- `canonical_symbol()` was called about 8.9 million times.
- `symbol_in_or_inherits()` rebuilt the complete class map for each call.
- function semantic summaries repeatedly scanned all functions to a fixed point.
- flow branches copied and merged complete scope maps.
- expression summaries and symbol resolution revisited AST subtrees.
- process workers exchanged large Python object graphs through pickle.

## Phase 0 — Preserve the baseline

Status: existing foundation, extend when each later phase lands.

### Work

1. Keep synthetic, real-checkout, and resident benchmarks separate.
2. Add counters for the unit of work changed by each phase; timing alone is not a
   sufficient correctness signal.
3. Save a current anti-monitor benchmark artifact after the external checkout is
   stable enough to provide repeatable source and diagnostic digests.
4. Retain byte parity checks against `--daemon never`.
5. Add focused microbenchmarks only for diagnosed hot paths; never substitute them
   for real-checkout gates.

### Exit gate

- The current full test/static/build suite passes.
- The benchmark reports exact source and diagnostic identity.
- A repeated unchanged daemon run reports no analysis/provider/policy work.

## Phase 1 — Choose concurrency from pending work

Status: complete.

### Problem

`ResidentCheckSession` chooses a worker limit from the total discovered source
count. The incremental analyzer may then send a one-file pending batch to the
Python adapter with a multi-worker request. Creating a fresh process pool for a
small batch costs more than the analysis and adds pickle traffic.

### Work

1. Treat the supplied `workers` value as a maximum, not a command to create that
   many workers.
2. Let `PythonAstAdapter`, which owns `ProcessPoolExecutor`, choose serial execution
   when the actual `sources` batch is below the existing parallel threshold.
3. Cap workers by the actual batch size.
4. Add tests proving that small batches do not instantiate an executor and large
   batches preserve ordered, deterministic output.
5. Re-run the resident ordinary-edit benchmark and compare exact output.
6. Only after measuring batch sizes around the threshold, decide whether the
   current threshold of 100 should change.

### Exit gate

- All correctness contracts pass.
- A one-file edit creates no process pool.
- Cold analysis does not regress by more than 5% at p50.
- Ordinary-edit latency improves measurably across at least five samples.

### Rollback trigger

Rollback or revise the selection policy if it changes result order, loses worker
failures, or causes a repeatable cold regression above the gate.

## Phase 2 — Canonical symbol and hierarchy indexes

Status: complete.

### Problem

Policy helpers repeatedly canonicalize the same configured candidates. In
particular, `symbol_in_or_inherits()` constructs a project-wide class dictionary
on every call and walks bases repeatedly.

### Work

1. Add project-revision-owned indexes for canonical configured symbols,
   `class_by_symbol`, direct bases, and ancestor closure.
2. Make `symbol_in()`, `matching_symbol()`, and `symbol_in_or_inherits()` use these
   indexes without scanning modules.
3. Ensure aliases and inheritance cycles have deterministic results.
4. Keep the public policy/context surface stable for built-in and external packs.
5. Add lookup call/scan counters and adversarial alias/cycle tests.

### Exit gate

- No policy helper performs a project-wide scan per target evaluation.
- Canonical reports match fresh pre-change fixtures exactly.
- Cold policy time improves without increasing resident RSS by more than 10%.

## Phase 3 — Dependency-driven function summaries

Status: complete.

### Problem

Effect, session-provider, and bulk-mapping summaries currently scan every function
until the whole project reaches a fixed point. A small change rebuilds this global
derived state in a new `PolicyContext`.

### Work

1. Build a canonical function call graph and its reverse edges once per revision.
2. Collapse strongly connected components so recursion has an explicit unit.
3. Compute summaries in component topological order.
4. On edits, seed a worklist with changed functions/components and propagate only
   when the public summary value changes.
5. Preserve prior summaries across resident revisions with explicit identity and
   invalidation rules.
6. Add recursive, mutually recursive, wrapper-chain, removal, and unresolved-call
   parity tests.

### Exit gate

- Unchanged function summaries are reused by identity/value.
- A leaf body edit does not scan unrelated functions.
- TX/external/session transitive rules retain exact coverage and diagnostics.
- No unbounded iteration is possible; component processing has explicit limits.

## Phase 4 — Reduce repeated AST and flow work

Status: complete.

### Problem

Fact extraction performs repeated generic AST visits, expression summarization,
scope priming, and full binding-map copies at control-flow joins.

### Work

1. Instrument visits per AST node category and scope size at every flow snapshot.
2. Add revision-local memoization for expression summaries and name resolution,
   keyed by node plus lexical/flow context.
3. Replace whole-project-independent scope copies with scope-local deltas or
   copy-on-write overlays.
4. Consolidate compatible extraction passes only where their traversal order and
   failure semantics can remain explicit.
5. Preserve CPython AST as the correctness oracle during this phase.

### Exit gate

- Repeated subtree visits and copied binding entries fall by a measured amount.
- Branch-heavy, comprehension, pattern-matching, closure, `global`, and `nonlocal`
  fixtures remain exactly equal.
- Cold analysis target: establish a new threshold after Phases 1–3; the initial
  directional target is 8 seconds or less for the current anti-monitor scale.

## Phase 5 — Definition-level incremental queries

Status: first production query family complete. Phase 5A and the opt-in 5B/5C
foundation are complete; 5D selectively reuses TX003 atomicity summaries and 5E
now covers mixed-edit differential testing, one-revision retention, and RSS plateau
measurement. General project-rule query reuse remains deliberately disabled until
extension packs can declare their semantic dependencies.

### Problem

Module-level reuse is not enough when a large module changes locally. Rebuilding a
new snapshot/context also discards derived caches whose actual inputs did not
change.

### Work

1. Define stable semantic identities and digests for definitions, calls, bindings,
   class bases, and public module interfaces.
2. Represent project indexes, provider capabilities, summaries, target selection,
   evaluations, assurance, and reporting as versioned derived queries.
3. Record dependencies while computing each query.
4. On a revision, invalidate from changed semantic inputs rather than changed file
   paths alone.
5. Stop propagation when a recomputed value is equal to its previous value.
6. Bound retained revisions and expose query hit/recompute/eviction counters.
7. Keep a fresh full-recompute oracle and continuously differential-test it.

### Safe implementation sequence

Phase 5 must not begin by treating an unchanged public signature as an unchanged
semantic dependency. A function-body change can alter a transitive effect or
session summary and therefore invalidate rules in callers even when imports and
signatures are identical. Implement the query layer in these independently
reversible slices:

1. **5A — identities and digests:** define and test versioned digests for module
   interfaces, definitions, calls, bindings, and summary values without changing
   invalidation behavior.
2. **5B — dependency recording:** record which semantic inputs each target,
   summary, provider result, and evaluation reads; keep module-level invalidation
   authoritative.
3. **5C — shadow invalidation:** compute query-derived impact beside the current
   module impact, expose counters, and fail differential tests if it would omit a
   recomputed value that changes.
4. **5D — selective reuse:** enable query-based reuse one query family at a time,
   beginning with target selection and local evaluations, with an immediate full
   recompute fallback on identity or capability mismatch.
5. **5E — retention and stress:** bound revisions and query entries, then run
   randomized add/remove/rename/body/signature/config/syntax edit sequences and a
   long-lived RSS plateau test before accepting the phase.

### Exit gate

- Body-only and public-interface edits have observably different impact sets.
- The fresh oracle and incremental engine match across randomized edit sequences.
- Directional targets on the current scale: leaf edit 0.5–0.8 seconds and shared
  edit 1–2 seconds, subject to a stable external checkout and p95 evidence.
- Resident memory remains bounded under long edit sequences.

## Phase 6 — Native acceleration decision

Status: measured; native implementation deferred.

### Option A: selective mypyc

Candidate modules are pure, typed computation with limited dynamic extension:

- flow and state merging
- symbol/relation index construction
- function-summary graph algorithms
- compact fact/range construction loops

Ship platform wheels plus a pure-Python fallback. Require report parity across
compiled and interpreted builds. The evaluation hypothesis is a 1.5–3x gain in
compiled sections and a 1.2–1.8x end-to-end cold gain; these are experiment targets,
not promises.

### Option B: Rust analysis kernel

A Rust experiment is justified only if the remaining target cannot be met with
algorithmic work and selective compilation. Do not replace only `ast.parse()`.
The useful boundary is a module-sized kernel containing parsing or AST ingestion,
scope/binding/control-flow construction, symbol resolution, expression summaries,
and compact immutable facts/indexes.

Requirements:

1. No Python/Rust call per AST node.
2. Batch input and compact output with measured serialization bytes/time.
3. Stable semantic ABI and capability versions before implementation.
4. Python policy/plugin compatibility remains at the outer boundary.
5. Cross-platform wheels, pure fallback, fuzzing, ecosystem differential tests,
   and identical engine-issue behavior are release requirements.

### Decision gate

Choose native work only from a new profile after Phase 5. Estimate maximum
end-to-end gain using the measured fraction of time inside the proposed kernel.
Reject the rewrite if boundary, maintenance, and compatibility costs cannot meet a
written latency target.

The current decision is to keep the pure-Python architecture. On the accepted
anti-monitor checkout, a single-worker fresh profile spends 31.390 of 42.581
profiled seconds in analysis (73.7%), so a broad native analysis kernel could be
material. The actual four-worker cold run spends only 5.366 of 10.991 seconds in
analysis (48.8%): even an ideal infinitely fast kernel cannot improve the complete
run beyond 2.05x, while a realistic 3x kernel would yield about 1.48x. For the
ordinary edit, analysis is 0.499 of 1.706 seconds (29.2%), limiting a 3x kernel to
about 1.24x. Project assembly, providers, project-wide rules, assurance, discovery,
and reporting are still separate Python costs. That evidence does not justify the
semantic ABI, cross-platform wheel, fallback, fuzzing, and plugin-compatibility
burden yet. Revisit only after those algorithmic/incremental costs are reduced and
a written cold-latency target requires more than the pure-Python path can deliver.

## Execution order

The authoritative sequence is:

1. Phase 1: pending-work concurrency
2. Phase 2: canonical and hierarchy indexes
3. Phase 3: dependency-driven function summaries
4. Phase 4: AST/flow repeated-work reduction
5. Phase 5: definition-level query graph
6. Phase 6: measured native acceleration decision

After each phase:

1. run focused tests;
2. run the full static/test/build suite;
3. run canonical and resident real-checkout benchmarks;
4. verify exact output and diagnostic digest parity;
5. record the result here or in a linked versioned benchmark artifact;
6. update the next phase using the new profile rather than the old assumption.

## Progress log

| Date | Phase | Change | Correctness | Performance | Decision |
|---|---|---|---|---|---|
| 2026-09-05 | research | official-tool comparison and local profile | worktree unchanged | baseline recorded above | begin Phase 1 |
| 2026-09-05 | 1 | select serial/process execution from the actual pending batch and cap workers to batch size | five-sample before/after stdout, stderr, exit-code, and recomputation counters match | ordinary wall 2.871 s -> 2.689 s (-6.3%) and analysis 740 ms -> 639 ms (-13.6%); shared analysis 860 ms -> 789 ms (-8.3%); restart wall 18.143 s -> 17.257 s (-4.9%) | accepted; proceed to Phase 2 after full-suite verification |
| 2026-09-05 | 2 | build canonical class, direct-base, ancestor, and candidate-symbol indexes once per policy revision; route inheritance, DTO, response mapping, and symbol matching through them | five-sample before/after stdout, stderr, exit-code, and recomputation counters match; cycle and no-rescan contracts pass | ordinary policy 1.640 s -> 1.110 s (-32.4%), wall 2.689 s -> 2.460 s (-8.5%); shared policy 2.505 s -> 1.809 s (-27.8%), wall 4.850 s -> 4.214 s (-13.1%); restart policy 6.886 s -> 4.692 s (-31.9%), wall 17.257 s -> 13.319 s (-22.8%); peak RSS +1.2% | accepted; proceed to Phase 3 after full-suite verification |
| 2026-09-05 | 3 | replace global fixed-point scans with non-recursive SCC evaluation; retain direct summaries and call edges across revisions; rescan impacted modules only; stop propagation when summary values remain equal | recursive, 2,000-call-chain, unchanged-summary, changed-effect reverse-propagation, and five-sample output parity contracts pass | ordinary wall 2.460 s -> 2.333 s (-5.2%); shared wall 4.214 s -> 3.658 s (-13.2%) and policy 1.809 s -> 1.285 s (-29.0%); restart wall 13.319 s -> 12.535 s (-5.9%) and policy 4.692 s -> 4.181 s (-10.9%); peak RSS +1.7% | accepted; proceed to Phase 4 after full-suite verification |
| 2026-09-05 | 4 | fast-path equal flow joins; use copy-on-write scope maps for branch snapshots; index import edges by importer instead of rescanning the project edge list | focused flow/static contracts and five-sample stdout, stderr, exit-code, and recomputation-counter parity pass | single-worker `_merge_flows()` cumulative time 6.086 s -> 2.035 s (-66.6%) and `analyze_module()` 34.833 s -> 30.785 s (-11.6%); real restart analysis 5.817 s -> 5.680 s (-2.4%), wall 12.535 s -> 11.926 s (-4.9%); shared wall -1.5%; ordinary wall +0.7%; peak RSS +2.4% | accepted; the directional cold-analysis target remains met at 5.680 s; proceed to Phase 5 after full-suite verification |
| 2026-09-05 | 5A–5C foundation | add versioned, location-independent semantic digests; add domain-level query/input identities and dependency propagation; build function-summary dependency snapshots and an on-demand shadow soundness comparison | coordinate, source-hash, body-only, signature, call, ordering, recursion, transitive-effect, and deliberately-unsound graph contracts pass; full suite passes with 1,279 tests | retained normal path versus Phase 4: ordinary 2.349 s -> 2.311 s (-1.6%), shared 3.604 s -> 3.617 s (+0.4%), restart 11.926 s -> 11.635 s (-2.4%), peak RSS -3.1%; all five-sample output hashes and exit codes match | foundation accepted; keep dependency construction off the normal path until selective reuse pays for it; begin 5D with TX003 write summaries |
| 2026-09-05 | 5D–5E | replace TX003's per-edit global fixed point with bounded incremental write summaries; group calls once per invalidated module; add seeded add/remove/rename/body/signature/config/syntax differential coverage; expose one-revision retention; classify RSS plateaus | 1,284 tests pass; every mixed-edit step matches a fresh run; five-sample stdout, stderr, and exit-code digests match; recursive and decreasing-cycle summary contracts pass | versus Phase 4: cold 11.616 s -> 10.991 s (-5.4%), ordinary 2.349 s -> 1.706 s (-27.4%), shared 3.604 s -> 3.302 s (-8.4%), restart 11.926 s -> 11.414 s (-4.3%); 30 unchanged checks hold RSS at 858.6 MiB after the first sample | first query family accepted; keep generalized project-rule reuse off until extension dependency contracts make it sound |
| 2026-09-05 | 6 decision | profile accepted fresh and ordinary paths and calculate Amdahl bounds for a native analysis kernel | profiles preserve the accepted implementation and use the same 1,213-source checkout | analysis is 48.8% of actual cold wall and 29.2% of ordinary-edit wall; estimated complete-run gain from a 3x kernel is about 1.48x cold and 1.24x ordinary | defer native code; continue algorithmic work at project assembly, providers, project-wide rules, assurance, discovery, and reporting |

The Phase 1 acceptance run used anti-monitor commit
`72279e5e5556ed4bc8c80d567878953b4dc40ae9` with 1,213 reparsed modules on
cold/restart paths. The five samples per timed edit phase were collected across
two isolated benchmark invocations (three plus two) against the same detached
worktree. The ordinary-edit p95 improved from 3.001 seconds to 2.769 seconds.
The shared-edit wall median moved from 4.773 seconds to 4.850 seconds even though
its analysis median improved; policy evaluation dominates that scenario and is a
later-phase target. No phase changed the canonical diagnostic digest.

The Phase 2 acceptance run used the same anti-monitor commit and five samples per
timed phase. A profile reduced `symbol_in_or_inherits()` from 4.737 seconds over
2,450 calls to approximately 0.005 seconds by replacing per-call project scans
with indexed set lookups. An attempted cache of complete match results was removed
before acceptance because hashing large candidate tuples cost more than the saved
work. This rejected experiment is intentionally recorded so it is not repeated.

The Phase 3 acceptance run used the same checkout and five samples. Four of five
ordinary-edit samples were at or below 2.459 seconds, while one 3.290-second
system-delay sample raised the small-sample p95 above the Phase 2 run; the median
still improved by 5.2%. Two earlier candidates were rejected because they improved
cold runs while regressing ordinary edits: SCC-only evaluation, then direct-summary
reuse without final-summary reuse. The accepted design also reuses the complete
prior summary map when a recomputed direct value and call graph are unchanged.

The Phase 4 acceptance run used the same checkout and five samples. Profiling was
performed with one analysis worker so Python call topology remained visible;
unprofiled resident measurements remain the acceptance evidence. The equal-join
fast path produced most of the gain. Copy-on-write snapshots removed eager nested
map copies, while the import-edge index removed a separate linear project scan.
All retained changes preserve the CPython AST path and stay below the 10% memory
growth gate. The 0.7% ordinary-edit wall movement is within run noise and its
analysis median improved from 683 ms to 675 ms.

The first Phase 5 dependency recorder was deliberately rejected after measurement:
constructing the complete function-summary graph on every normal policy run made
ordinary edits 6.3% slower and shared edits 12.6% slower. The retained design
builds this graph only for shadow/differential runs, so the ordinary path remains
within Phase 4 noise. A single-worker ordinary-edit profile then identified the
first 5D query family: `TX003` consumed 1.824 of 2.891 profiled policy seconds and
called its database-write classifier 373,312 times because it recomputed a global
fixed point after every edit. Phase 5D should replace that loop with bounded,
dependency-driven per-function write summaries before enabling general evaluation
reuse.

Phase 5D initially regressed shared edits and restart runs because call ownership
was computed by scanning every module call once for every function. Grouping calls
by enclosing function in one pass removed that accidental quadratic work. The
accepted five-sample run reduced TX003 from 1.824 profiled seconds in the earlier
ordinary path to 0.148 seconds, including 0.134 seconds to update the summary
state. A separate 30-check resident run ended one MiB below its starting RSS and
remained flat for the final 29 samples. The benchmark schema now reports growth,
tail span, tolerance, and a stable/unstable plateau classification rather than
requiring a visual judgment.
