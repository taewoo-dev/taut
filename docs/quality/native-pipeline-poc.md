# Rust policy pipeline expansion

This experiment extends the opt-in Rust backend beyond transitive function summaries.
Python remains the default. The extension is now `taut-summary-core` 0.2.0; the original
row-based summary API retains contract version 1, and the new columnar input API uses
batch version 2. Older extension wheels fail explicitly in the new host.

## Measured targets

A cProfile diagnostic on the frozen 1,224-source antimonitor snapshot identified function
summary preparation and transaction atomicity analysis inside shared-edit policy work.
The original Rust v1 host spent 1.295 instrumented seconds in function summary building
and 0.863 seconds in atomicity summary building. The enclosing policy stage took 3.941
instrumented seconds. Nested timings overlap and must not be added; profiler timings
are not benchmark wall times. First-check source parsing remains Python and is outside
this bounded change.

## Changes

Function summaries now receive changed module definitions, primitive call columns,
callback-effect masks, and ordered provider matchers. Rust groups calls by lexical owner,
selects owned callees, merges definite/uncertain effects, matches providers, recognizes
bulk operations, and performs graph propagation. Python no longer constructs intermediate
per-function summary objects or rescans unchanged module functions for the owned-symbol
table. Alias and callback interpretation and catalog resolution remain Python.

Atomicity now has an immutable Rust state. Rust handles decorator/context boundary tests,
write-method and model-root classification, contribution construction, ambiguous candidate
upper bounds, reverse invalidation, and the bounded write-range fixed point. Provider
query confidence and canonical names arrive from Python. Transaction boundaries use exact
canonical equality, while function-summary provider matching retains ordered dotted-prefix
matching. These are intentionally different contracts.

Python policy rules still receive `FunctionSemanticSummary` and `WriteRange` values.
Direct function summaries, graphs, and atomicity contributions are read-only lazy views.
Unchanged native records share `Arc` ownership without retaining parent states. Module-set
and session configuration changes rebuild state. Column lengths and effect/query encodings
are validated before a new state is returned; failed updates preserve previous snapshots.

An initial row-per-call bridge regressed shared-edit performance. The retained implementation
uses columns instead, avoiding one Python tuple per call and using immutable empty tuples
for empty candidate/context sequences. This changes where input cost is accounted: the
Python preparation timer includes column construction, and the old separate row-encoding
timer is nearly zero. Compare combined preparation/encoding, not either field alone.

The differential suite also exposed an existing Python atomicity bug: a removed caller
could be requeued via the old reverse graph and raise `KeyError`. The Python reference now
excludes deleted functions from that queue. A separate default-backend regression test
covers the fix; correctness tests were not weakened to accommodate the native engine.

## Validation and reproduction

```bash
bash scripts/test.sh
bash scripts/test_native_summary.sh
```

The native gate builds an isolated wheel, runs Rust fmt/Clippy/tests, the full Python suite
with that wheel, and installed Python/native wheel report parity. Differential tests cover
300 function-graph revisions, 300 complete-report revisions, and 300 atomicity revisions,
plus exact-versus-prefix boundaries, ambiguous candidates, cross-module effect removal,
old-state lifetime, and malformed column input followed by a successful retry.

For a local installation, use a dedicated output directory so earlier wheel versions are
not accidentally installed together:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export PYO3_PYTHON="$PWD/.venv/bin/python"
uvx maturin==1.13.0 build --release --locked \
  --manifest-path native/summary_core/Cargo.toml --out /tmp/taut-native-v2-wheel
uv pip install --python .venv/bin/python /tmp/taut-native-v2-wheel/taut_summary_core-0.2.0-*.whl
```

The existing Python API opt-in now selects both native summary engines:

```python
from pathlib import Path
from taut.check_service import CheckRequest, ResidentCheckSession

root = Path("/path/to/project")
with ResidentCheckSession(root, summary_backend="rust") as session:
    result = session.check(CheckRequest(root))
```

Python remains the default for sessions, the CLI, and the daemon.

Performance comparison uses a separate environment built from `907efe9` plus the saved
0.1.0 wheel for Rust v1. The current Python and Rust v2 use the same updated Python host.
Both environments use CPython 3.14.0 and msgspec 0.21.1. Run order is Python/v1/v2 followed
by v2/v1/Python, each in a fresh process with a disposable snapshot copy. Each version has
two first-check samples and ten ordinary/shared edit samples. First-check results are
small-sample diagnostics, not evidence of a universal speedup.

```bash
.venv/bin/python scripts/benchmark_native_pipeline.py SNAPSHOT OUTPUT.json \
  --baseline-python V1_ENV/bin/python
.venv/bin/python scripts/validate_native_pipeline.py SNAPSHOT VALIDATION.json
```

The validation runner performs 50 semantic warmup transitions, 100 unchanged checks, and
50 semantic changes per backend before the native candidate is compared with fresh Python
on 14 real-project edits. The latter compares complete report values, text/JSON stdout,
stderr, and exit codes. RSS uses the existing max(8 MiB, 3%) endpoint/tail-range test;
process RSS is not native allocated bytes. All target edits are in temporary copies;
target application/database code is never executed.

## Results

Implementation: `ebab348`, compared with v1 at `907efe9`. Measurements were collected on
2026-09-06 on macOS ARM64. Full evidence is in [native-pipeline-poc.json](native-pipeline-poc.json).

Median whole-check seconds:

| Scenario | Python | Rust v1 | Rust v2 |
| --- | ---: | ---: | ---: |
| First check (2 samples) | 10.691 | 11.603 | 10.324 |
| Ordinary edit (10 samples) | 1.412 | 1.355 | 1.355 |
| Shared edit (10 samples) | 2.710 | 2.490 | 2.295 |

Shared edits were 7.8% shorter than v1 and 15.3% shorter than Python in this run.
Ordinary edits were effectively unchanged versus v1. First checks have too few samples
to support a general cold-start claim. Two balanced execution orders reduce ordering bias
but do not establish statistical significance or performance on other repositories.

For shared edits, median policy time fell from 1,750.7 ms in v1 to 1,244.1 ms in v2
(28.9%). The function-summary boundary total fell from 521.71 ms to 235.53 ms (54.9%).
Its combined Python preparation/encoding fell from approximately 425.35 ms to 198.02 ms;
native compute increased from 12.11 ms to 26.09 ms because Rust now performs more work.
These are independent medians; they need not sum. Analysis-stage timing also varied
(243.0 ms versus 520.9 ms), although source analysis was not moved to Rust. The policy
improvement therefore does not translate directly into the same whole-check percentage.

The initial row-based bridge measured 2.810 s for shared edits versus 2.645 s for v1 in
that separate run. Its evidence is retained as exploratory data and is not pooled with
the final columnar measurements. Lower intermediate-object overhead motivated the column
layout; these experiments do not isolate allocation or garbage collection as the cause.

The final default gate passed 1,403 tests (25 optional skips), with 90.46% coverage. The
native gate passed 1,428 Python tests with 90.65% coverage and four Rust tests, plus fmt,
Clippy, strict Python type checks, conventions, self-policy, and installed-wheel parity.

All 14 real-project semantic edits matched fresh Python report values, text/JSON output,
stderr, and exit codes. All 1,225 captured source/config file hashes remained unchanged.

Whole-process resident memory (MiB), measured after 50 warmup transitions per backend:

| Backend / phase | Checks | First | Last | Median | Tail range | Stable |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Python unchanged | 100 | 763.0 | 700.6 | 700.9 | 114.0 | No |
| Rust unchanged | 100 | 872.0 | 757.7 | 807.6 | 276.5 | No |
| Python mixed edits | 50 | 700.7 | 765.0 | 764.0 | 15.8 | No |
| Rust mixed edits | 50 | 757.7 | 875.3 | 874.5 | 0.7 | No |

Neither backend passed the predeclared endpoint/tail-range criterion. Unchanged runs
failed the tail-range check; mixed runs failed the endpoint-growth check. Rust mixed
edits settled within a narrow tail range, but that does not override the failed criterion.
The mixed-edit Rust median was about 14.5% higher than Python. These single sequential
RSS runs neither demonstrate a leak nor establish its absence; resident pages and Python
allocator behavior are included. There is no demonstrated memory improvement.

The result supports retaining this as an optional acceleration for policy-heavy shared
edits. It does not justify changing the default backend: ordinary edits did not improve
versus v1, parsing remains Python, and memory needs separate allocation/lifetime analysis
and repeated steady-state measurements before broader adoption.
