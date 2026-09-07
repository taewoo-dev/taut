# Resident memory follow-up

Date: 2026-09-05. Original performance baseline: `452c5be`; preceding implementation:
`5e83712`; final engine: `29c6edc` (also includes `fbc64e4` and `11abfa6`). Package remains 0.9.0,
with unreleased changes.

## Why the earlier memory result was insufficient

The [previous acceptance](performance-implementation.md) met latency and correctness goals,
but RSS reductions were below 10% and the full-series plateau checks failed. Cold fresh-oracle
subprocesses ran during the first five mixed-state samples. Those observations remain valid
as recorded; this follow-up uses a different, explicitly warmed protocol and does not replace
or relabel the previous failures.

An initial session-object census found that syntax-context sharing removed about 182,000
objects, while retained index tuples and empty assurance-evidence sets added substantial state.
There were also 184,857 symbol-ID objects for 68,885 distinct values and 16,156 function-effect
summary objects for only 74 distinct values in this snapshot.

## Changes

- Compare index inputs from already-retained module facts only for replaced contributions.
  Unchanged contributions compare by identity. Remove persistent duplicate comparison tuples;
  the internal assembly-state schema is now 2 and older state rebuilds safely.
- Store module assurance evidence only for domains with actual evidence. The final aggregate
  still contains all configured domains, including empty ones, and all global checks still run.
- Share symbol IDs produced by one Python resolver. The pool dies with extraction and cannot
  cross source revisions. Occurrence provenance and identity remain distinct where required.
- Share equal immutable function summaries within one summary build, including across direct
  and transitive maps. Equality includes access paths, providers, bulk operations, and uncertain
  effects. Pool keys have no source locations; no global cache retains old revisions.
- Close the Python extractor on success and failure to break the expression summarizer's bound
  callback references back to its owner. A small reproduction with automatic GC disabled showed
  that the preceding extractor survived after analysis and disappeared only after `gc.collect()`.
  The regression test now verifies immediate release while returned facts remain usable, without
  invoking GC. This removes a confirmed delayed-release cycle, not a demonstrated unbounded leak.

Public object layouts, policy behavior versions, and wire formats remain unchanged.
Existing serialized module caches remain compatible; previously stored duplicate object values
are not retroactively compacted by the resolver pool. Fresh extraction creates the shared
values, and pickle preserves their sharing. The measurements below use disposable fresh copies.

## Reproducible measurements

[measure_retained_objects.py](../../scripts/measure_retained_objects.py) walks the strong
object graph reachable from a successful resident session, deduplicating by object identity.
It excludes classes, modules, functions, and code objects; selected immutable values are also
hashed to count distinct values. That may populate their existing hash caches. A forced single
analysis worker avoids process-pickle differences. It reports Python object counts and sums of
`sys.getsizeof`, not RSS, total retained allocations, or peak memory. Managed instance
dictionaries, allocator overhead, and excluded process globals are not fully represented.
The census process's own traversal sets are not part of the measured session graph.

```sh
PYTHONPATH=/absolute/engine/src /absolute/repo/.venv/bin/python \
  /absolute/repo/scripts/measure_retained_objects.py /absolute/snapshot /absolute/objects.json
```

The same script and interpreter inspect all three engines. The original and final engines then
run sequentially through [measure_acceptance.py](../../scripts/measure_acceptance.py), harness
v3, with `--memory-warmup-cycles 10 --memory-checks 200 --mixed-checks 100 --repeats 5
--cold-repeats 1 --probe-checks 5`. The original repository is not modified; the frozen
1,224-source anti-monitor snapshot is copied for each daemon experiment.

The warmup cycles safe code, unsafe lambda invocation, unsafe synchronous callback invocation,
safe thread offloading, and removal ten times. The first cycle generates all five fresh JSON
oracles before RSS sampling begins. Subsequent warmups and all 100 measured semantic edits
compare exact JSON stdout/stderr/exit code against those states. After sampling, five more
checks each execute a new fresh oracle. No target application code is executed.

The plateau rule is unchanged: growth from first to last and the second-half RSS span must both
be at most `max(8 MiB, 3% of first RSS)`. RSS reduction compares full-series medians. Five edit
timing samples are regression observations; the single cold start cannot establish a cold p95.
This remains a shared Mac experiment, not an isolated allocator or leak proof.

## Results

### Session-object census

| Measure | Original `452c5be` | Prior `5e83712` | Current `29c6edc` |
|---|---:|---:|---:|
| Reachable objects | 5,051,872 | 4,983,792 | 4,629,751 |
| Sum of shallow sizes | 336.14 MiB | 343.18 MiB | 308.63 MiB |
| Tuples | 614,283 | 698,829 | 611,426 |
| Symbol IDs | 184,857 | 184,857 | 115,258 |
| Distinct symbol-ID values | 68,885 | 68,885 | 68,885 |
| Function summaries | 16,156 | 16,156 | 74 |
| Distinct summary values | 74 | 74 | 74 |
| Frozensets | 105,282 | 105,867 | 57,621 |

The shallow-size sum decreases about 10.1% from the preceding implementation and 8.2% from
the original baseline. This is bounded structural evidence, **not a 10% RSS reduction claim**.
The number of distinct values remains unchanged in the targeted symbol/summary families.
Sparse evidence reduces retained mutable sets from 15,912 to 1,101 versus the preceding version.

### Warmed resident RSS

The intermediate `11abfa6` run completed with medians of 772.92 MiB (unchanged) and
774.05 MiB (mixed); both plateau checks passed, but neither phase met the 10% reduction
target against the original baseline. Its data is retained as a superseded candidate, not
discarded. The candidate alone was repeated after the confirmed extractor-cycle fix; the
original baseline remains the same completed run.

**Warmed stability passes; the 10% RSS reduction target remains unmet.** Full raw runs,
the superseded candidate, source hashes, and object-census rows are recorded in
[memory-followup.json](memory-followup.json).

| RSS phase | Original median | Final median | Reduction | Original / final plateau |
|---|---:|---:|---:|---|
| 200 unchanged checks | 756.45 MiB | 773.20 MiB | −2.21% (increase) | Pass / pass |
| 100 semantic edits | 851.05 MiB | 773.63 MiB | 9.10% | Pass / pass |

The final second-half RSS spans are 1.97 MiB unchanged and 7.41 MiB mixed, within their
unchanged 3%-or-8-MiB allowances. This supports a plateau for these bounded, warmed runs;
it is not a universal leak proof. The original unchanged run dropped from about 864 MiB to
756 MiB even after oracle priming, so cold-oracle interference alone does not explain the
earlier RSS variation. The data does not isolate GC, allocator residency, or OS effects.

Do not attribute the entire mixed-RSS difference to the cycle fix: the intermediate candidate
already measured 774.05 MiB mixed, close to the final 773.63 MiB. The cycle fix is supported
by the disabled-GC lifetime regression; a separate RSS benefit from it is not established.

| Edit latency | Original median / p95 | Final median / p95 |
|---|---:|---:|
| Ordinary comment edit, 5 samples | 2.026 / 2.134 s | 1.311 / 1.711 s |
| Shared comment edit, 5 samples | 4.617 / 5.044 s | 2.586 / 2.869 s |

These observations preserve the 2/4-second edit targets without a p95 regression versus this
baseline sample. They do not replace the prior 20-sample experiment with equivalent confidence.
All measured checks and warmups match their applicable fresh oracles; all five final per-edit
fresh JSON comparisons pass. Both accepted daemons and the superseded candidate daemon stop
successfully. Source hashes match between each accepted engine's census and daemon run.

## Remaining boundary

The completed work removes measured redundancy and a confirmed delayed-release cycle, and
establishes the prescribed plateau under the new warmed protocol. It does **not** establish
the required 10% RSS reduction in both workloads. The next material investigation would need
allocation/allocator-residency measurements that separate live objects from unused heap pages;
additional value-sharing changes should follow that evidence. Public layout changes, a broader
state-storage redesign, and Rust remain outside this change. No thresholds were relaxed and
no successful-looking tail was substituted for a full-series result.

## Validation

`bash scripts/test.sh` passes on Python 3.14.0: **1,383 tests, 90.55% total coverage with branch
measurement**, repository conventions, Ruff formatting/lint, strict mypy/Pyright, strict
self-policy, wheel/sdist builds, and installed-wheel smoke checks. Regressions cover independent
source-version pools, shared pickle identities, distinct direct/approved-wrapper access paths,
and the existing 3 × 100 synthetic edit/fresh comparisons and snapshot-release checks.
Additional tests disable automatic GC and verify immediate extractor release on both successful
analysis and an injected failure, while successful returned facts remain usable.
