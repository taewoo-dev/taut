# Performance implementation and acceptance

Date: 2026-09-05. Baseline: `452c5be`; candidate engine: `9aac0ad`.
Package version remains 0.9.0; these are unreleased changes.

The subsequent [memory follow-up](memory-followup.md) investigates retained objects and repeats
RSS measurements under an explicitly warmed protocol. The original results below are preserved.

## Implemented scope

1. **Project assembly:** retain one validated contribution per current module. Reuse unchanged
   relations and resolution counts; reuse the project index only when every consumed input,
   including occurrence locations, compares equal. Imports, topology, and changed index inputs
   use the original index builder. The fresh assembler remains an independent oracle.
2. **Built-in provider propagation:** recompute changed modules first for the exact FastAPI and
   SQLAlchemy implementations. Unchanged router/model symbol exports permit reuse in dependent
   modules. Export changes, module-set changes, and declarative-base factory edits fall back to
   broad invalidation. Third-party implementations and subclasses retain the existing contract.
3. **Policy reuse:** ASYNC001 and TIME001 may reuse unchanged module results only when canonical
   symbols, database operations, complete function summaries, and callback facts compare equal.
   Existing policy/catalog/version/completeness checks still apply. This is a conservative
   equality certificate, not a general fine-grained dependency-query engine.
4. **Evidence reuse:** cache module feature evidence for assurance and module class/reference
   evidence for EXC001. Global checks still run; configuration changes invalidate evidence.
   Cache entries for removed or replaced modules are discarded on every revision, including
   incomplete-project paths where a rule returns early.
5. **Immutable sharing:** intern syntax contexts, source ranges, and provenance within one
   module extraction. Pools do not cross source revisions or live globally. Public dataclass
   layouts and serialized/wire formats are unchanged.
6. **Failure safety:** publish incremental source identities only after assembly succeeds.
   An incompatible assembly-state schema forces rebuilding. Tests cover retry after an injected
   assembly failure, version changes, syntax failure/recovery, and stale-object collection.

Commits: `3612b4f`, `5b2f5d0`, `962eeb9`, `1c92527`, `9aac0ad`.

## Acceptance method

The private anti-monitor snapshot contains 1,224 Python sources. Its captured source HEAD was
`14bf0c5efddc286db6e4127f28917b5f772f96c7`; the 1,225-file source/config manifest digest is
`36e3e64d3e88ce3562558744960a487a2227f0743bb3fec5d2678d3aa55a5562`.
It includes then-uncommitted work and is not equivalent to checking out that HEAD alone.
Every run copies the frozen snapshot to a disposable directory. No application/database code
is executed, and this experiment does not edit the original repository.

Run [measure_acceptance.py](../../scripts/measure_acceptance.py) with the repository's Python
environment and an absolute `PYTHONPATH` selecting either baseline or candidate source:

```sh
PYTHONPATH=/absolute/engine/src /absolute/repo/.venv/bin/python \
  /absolute/repo/scripts/measure_acceptance.py /absolute/snapshot /absolute/result.json
```

The accepted runs combine two sequential batches per engine: 10+10 edits per timing scenario
and 3+2 fresh daemon starts. Ordinary edits change a fixed-width trailing comment in
`alembic/env.py`; shared edits do so in `app/core/config.py`. Text stdout, stderr, and exit code
must exactly match a fresh, no-cache subprocess. These timing scenarios measure source-change
invalidation without a semantic change; they are not timings for every possible edit.

The second batch runs 200 unchanged checks and 100 semantic edits cycling safe code, an unsafe
lambda, an unsafe synchronous callback, safe thread offloading, and file removal. Each of the
five distinct states gets a fresh JSON oracle; all 100 results match its bytes and exit code.
The candidate then performs 30 additional edits, each compared to a newly executed fresh JSON
oracle. Unit/integration tests separately compare 3 seeds × 100 mixed synthetic edits and
check collection of prior snapshots after removal/reset.

The first candidate timing batch was superseded after the atomic assembly fix and repeated on
the final engine. Its raw data is retained separately and excluded from accepted aggregates.
The early baseline timing batch used harness v1; its comment-edit timing method is unchanged
in v2. Only v2 second batches count toward the semantic and long-run memory checks.

## Results

**Acceptance is partial: latency and correctness pass; the memory goals do not.**
All raw observations, excluded earlier candidate data, source hashes, and gate calculations
are retained in [performance-acceptance.json](performance-acceptance.json).

| Scenario | Samples per engine | Baseline median / p95 | Candidate median / p95 |
|---|---:|---:|---:|
| Fresh daemon start | 5 | 11.626 / 11.819 s | 11.394 / 11.496 s |
| Ordinary comment edit | 20 | 1.859 / 2.005 s | 1.332 / 1.499 s |
| Shared comment edit | 20 | 4.569 / 4.767 s | 2.487 / 2.819 s |

Ordinary and shared medians meet the 2/4-second limits, with approximately 28% and 46% reductions
in this experiment. Cold median and all three p95 values stay within the 10% regression limit.
p95 uses nearest rank; for 20 samples it is the nineteenth sorted value. These are sequential
shared-machine observations, not guarantees for other projects or semantic edits.

The second batches also measured unchanged checks (200 each: median 0.334 → 0.238 s) and
semantic edits (100 each: median 1.921 → 1.568 s). All candidate timing/semantic checks preserved
the relevant fresh oracle output, and all 30 additional per-edit fresh JSON comparisons passed.
All four accepted batch daemons stopped successfully.

Separate in-process JSON checks confirm one recomputed assembly contribution, 1,223 reused
modules, and a reused project index for both edits. In the shared edit, FastAPI and SQLAlchemy
each recompute one module rather than the 651-module impact set; the other three providers
still receive all 651. Policy reevaluations fall from the earlier baseline's 88,193 to 23,104,
with 214,407 reused. Ordinary-edit reevaluations remain 655. Both counter checks match fresh
JSON. Their stage timings are separate observations and must not be compared directly with
the earlier profiled stages as a speed ratio.

The final `bash scripts/test.sh` gate on Python 3.14.0 passes **1,380 tests with 90.55% total
coverage measured with branches**, repository conventions, Ruff format/lint, strict mypy and
Pyright, strict self-policy, wheel/sdist builds, and installed-wheel smoke checks. The frozen
snapshot's 1,225 source/config files were rehashed and all still match the capture manifest.

| RSS during long run | Baseline median | Candidate median | Reduction | Full-series plateau |
|---|---:|---:|---:|---|
| 200 unchanged checks | 841.19 MiB | 785.28 MiB | 6.65% | Both fail |
| 100 semantic edits | 844.68 MiB | 825.63 MiB | 2.25% | Both fail |

Neither RSS series meets the 10% reduction target. The unchanged candidate series decreases
overall but its second-half span is 40.22 MiB, exceeding the 26.16 MiB allowance. The mixed
candidate series starts at 662.50 MiB after a cold oracle and ends at 825.73 MiB, exceeding its
19.88 MiB growth allowance despite a narrow 2.66 MiB second-half span. The full criterion is
`last - first <= tolerance` and `second-half max - min <= tolerance`, where
`tolerance = max(8 MiB, 3% of first RSS)`. Baseline series also fail. These results neither
prove a leak nor establish the required plateau; a selected stable tail does not override them.

The next memory task is a controlled retained-object/allocation comparison and a separately
defined warmed RSS experiment that primes all oracle states before sampling. Preserve this
failed acceptance result when adding that evidence. Do not proceed to public dataclass-layout
changes or native implementation merely to chase a noisy RSS number.

## Limits and remaining work

- Assembly still creates/sorts flat global outputs. Retained per-module indexes also consume
  memory; this is not an entirely O(changed modules) pipeline.
- Effect reuse compares whole shared summary values. A changed effect still takes conservative
  broad invalidation. Extending precise dependency tracking needs separate measured evidence.
- RSS is observed with `ps` on a shared Mac. Cold oracle subprocesses run during the first five
  semantic states and can affect residency. Decreasing RSS and later increases do not by
  themselves identify a Python leak or prove stable retained memory. Preserve the full-series
  plateau result rather than selecting a convenient tail.
- Rust/native implementation, public layout changes, and a disk-cache redesign remain deferred.
  This work does not establish real-project detection accuracy or organizational adoption.
