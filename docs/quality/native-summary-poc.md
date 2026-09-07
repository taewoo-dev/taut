# Optional Rust function summary core PoC

This is the historical 0.1.0 experiment. The [0.2.0 pipeline expansion](native-pipeline-poc.md)
adds columnar input preparation and native atomicity analysis, with new measurements and
installation instructions. The scope and results below describe v1 only.

The Python API now has an opt-in Rust implementation of function effect propagation.
The default remains Python. Parsing, fact extraction, callback interpretation, policy
rules, atomicity analysis, rendering, and the daemon protocol remain Python-owned.

Implementation: `a9c892a` plus summary-interning fix `32d5490`, based on `598ad71`. Both measured backends use the same
implementation checkout, with explicit backend selection. The original Python graph
and summary algorithm remains an independent correctness reference. This comparison
does not attribute the earlier Python optimizations to Rust.

## Boundary and ownership

`ResidentCheckSession(..., summary_backend="rust")` and
`run_check_request(..., summary_backend="rust")` select the extension. A missing or
incompatible extension raises an error; there is no automatic Python fallback.
Existing positional arguments and the default Python distribution remain compatible.

Python resolves calls and callbacks and prepares a batch of changed functions. Each
row contains the canonical function and module names, owned callees, explicit effect
and direct-access masks, uncertain effects, provider names, and bulk operation names.
Contract version 1 has a fixed eight-effect bit order. Direct access dominates an
approved wrapper; uncertainty is stored separately from definite effects.

Rust owns immutable function records, indexed forward/reverse graphs, SCC traversal,
affected-symbol closure, and propagated summaries. Computation uses `Python::detach`
after typed input conversion and does not call Python. Both old and new reverse edges
contribute to invalidation, so removing a call or effect can remove propagated effects.
Unchanged function records and reusable summary values use `Arc` sharing. A state does
not retain its parent state. Failed input validation leaves the old state intact.

`State.build(rows)` constructs a snapshot; `state.advance(changed_modules, rows)`
replaces the named modules, including removal by an empty batch. A change to the module
set triggers a full build at the Python boundary. Session configuration, catalog, and
provider identity changes reset the session before subsequent analysis.

Final summary values are exported once per distinct native value and bound to Python
function IDs in a bulk operation. Python policy checks read the usual
`FunctionSemanticSummary` values. Direct summaries and the call graph have read-only,
lazily materialized bulk views for diagnostic/dependency consumers. Mapping equality
compares semantic values, not native IDs. No native state is persisted to disk.

The PoC rebuilds integer graph indices and SCC structure per computed revision, then
reuses unaffected propagated summaries. It shares immutable function records rather
than implementing a persistent indexed graph or module arena. Python still builds the
canonical owned-symbol table and transfers string identifiers. These costs are part of
the chosen boundary and are included in the measurements.

## Build and verification

Validated locally on Apple Silicon, CPython 3.14.0, Rust 1.93.1, PyO3 0.29.2, and
Maturin 1.13.0. Cargo dependencies are locked in `native/summary_core/Cargo.lock`.
The extension wheel is CPython/platform specific; an abi3 wheel and a cross-platform
wheel matrix are outside this PoC.

```bash
bash scripts/test.sh
bash scripts/test_native_summary.sh
```

The native gate checks Rust formatting, Clippy with warnings denied, Rust unit tests,
the Python suite with the extension installed, and report parity between installed
Python/native wheels in an isolated environment. It builds the native wheel separately
from the existing Hatchling package. The default gate runs without installing Rust.

For a persistent local extension installation:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export PYO3_PYTHON="$PWD/.venv/bin/python"
uvx maturin==1.13.0 build --release --locked \
  --manifest-path native/summary_core/Cargo.toml --out /tmp/taut-native-wheels
uv pip install --python .venv/bin/python /tmp/taut-native-wheels/*.whl
```

`uv sync` may remove this extra package. The native gate supplies its freshly built
wheel explicitly and does not depend on it remaining installed.

Validation includes three seeds × 100 random graph revisions compared across Python
fresh/incremental and Rust fresh/incremental; a separate three seeds × 100 revision
suite compares complete reports, text/JSON stdout, stderr, and exit codes across those
four paths. Cases cover cycles, call removal, function/module addition/removal and
renaming, syntax errors/recovery, configuration changes, callbacks, access precedence,
provider/bulk information, invalid input, reset/close, and old-state lifetime. Rust
unit tests also exercise a 10,000-function chain without recursion.

The final pure-Python gate passed with 1,401 tests, 16 optional skips, and 90.48%
branch-aware coverage. With the native wheel installed, all 1,417 tests passed with
90.61% coverage. Rust formatting, Clippy, three Rust unit tests, strict Python static
checks, self-policy checks, package builds, and installed-wheel parity all passed.

## Measurement protocol

```bash
.venv/bin/python scripts/benchmark_native_summary.py /tmp/native-synthetic.json --synthetic
.venv/bin/python scripts/benchmark_native_summary.py /tmp/native-real.json --snapshot SNAPSHOT
```

The real-project runner copies the frozen 1,224-source antimonitor snapshot into a
temporary directory for each backend and runs backends sequentially in separate
processes. It never imports or executes target application code. It checks the snapshot
file manifest before/after. The original antimonitor working directory is not used.

Each backend runs five first checks, 20 ordinary edits (`alembic/env.py`), and 20 shared
edits (`app/core/config.py`). Fifty semantic transitions warm the resident state before
200 unchanged checks and 100 semantic modifications. Thirty additional native edits
are compared with fresh Python analysis on each edit, including text and JSON output.
The Python baseline does not redundantly compare itself with another fresh Python run.

The native phase tuple is: direct-input preparation, row encoding, FFI call overhead,
pure Rust compute, bulk result restoration, and their sum. FFI overhead is measured by
subtracting the Rust internal timer from the synchronous call duration. The phase sum
ends before the final Python state-container construction; end-to-end check timings
include that construction and all other pipeline work. Cold means a new resident
session, not an OS disk-cache flush. P95 is a nearest-rank sample statistic.

RSS measures the whole resident process, including Python restored values, Rust
allocations, and allocator retention. Native ownership statistics report function,
forward-edge, reverse-edge, and distinct-summary counts; they are not allocated-byte
measurements. A phase is stable when both its end-minus-start and its second-half
range are at most `max(8 MiB, 3% of first RSS)`. The threshold is unchanged.

Synthetic cases use 1k/10k/100k-function chains, shared leaves, and cycles. They compare
Rust with an independent Python SCC/mask-propagation reference, including Python
identifier/graph conversion and native FFI/export. This restricted workload has one
effect bit and no provider/bulk payloads. Its speedup is not a full-engine speedup.

## Results and decision

Raw samples, source-file hashes, native wheel hash, ownership counts, and the preserved
snapshot manifest digest are in [native-summary-poc.json](native-summary-poc.json).
All 30 real-project changes matched fresh Python analysis, including report values,
text/JSON stdout, stderr, and exit code. All 1,225 originally captured source/config
files remained unchanged. The runner also hashed 18 pre-existing `.git` metadata files;
those are excluded from the temporary benchmark copies.

| End-to-end check | Python median | Rust median | Observed change | Python/Rust p95 |
| --- | ---: | ---: | ---: | ---: |
| First check, 5 sessions | 12.627 s | 10.589 s | 16.1% shorter | 13.654 / 10.956 s |
| Ordinary edit, 20 samples | 1.413 s | 1.265 s | 10.5% shorter | 1.641 / 1.495 s |
| Shared edit, 20 samples | 2.476 s | 2.589 s | 4.6% longer | 2.816 / 2.839 s |

These are observations from one Python-then-Rust sequence, not randomized paired
measurements. Run order, CPU scheduling, OS cache state, and machine activity can
influence them. In particular, the first-check difference cannot be assigned entirely
to Rust from this experiment. The result does **not** establish a consistent whole-engine
speedup.

| RSS phase | Python median | Rust median | Observed change | Python/Rust stable |
| --- | ---: | ---: | ---: | --- |
| 200 unchanged checks | 706.48 MiB | 760.05 MiB | 7.6% larger | no / yes |
| 100 code modifications | 771.36 MiB | 833.12 MiB | 8.0% larger | yes / yes |

The Python unchanged phase had a 92.89 MiB second-half range, above its 23.13 MiB
threshold. Its median is therefore an unstable reference. Both mixed phases passed the
unchanged stability criterion, but native residency was larger. This PoC does **not**
meet the earlier 10% RSS-reduction goal. RSS alone cannot attribute the difference to
Rust data structures, Python restoration, GC, or allocator/OS retention. Native counts
at the end of the mixed phase were 8,078 functions, 12,752 forward edges, 12,752 reverse
edges, and 60 distinct retained propagated summary values.

| Native boundary phase, median | First check | Ordinary edit | Shared edit |
| --- | ---: | ---: | ---: |
| Python direct-input preparation | 487.94 ms | 109.36 ms | 368.20 ms |
| Python row encoding | 38.01 ms | 0.018 ms | 32.38 ms |
| FFI call overhead | 2.70 ms | 0.39 ms | 2.68 ms |
| Pure Rust computation | 8.59 ms | 9.02 ms | 12.04 ms |
| Bulk Python result restoration | 3.86 ms | 4.09 ms | 4.00 ms |
| Boundary total before final state containers | 540.52 ms | 122.96 ms | 517.09 ms |

Each row is an independent sample median, so component medians need not sum to the
median total. The Python preparation side dominates the measured native boundary;
FFI call overhead and the Rust kernel are small. Further kernel-only tuning is unlikely
to materially change whole-check time at this boundary.

At 100,000 functions, the restricted synthetic reference took 0.449/0.568/0.358 seconds
for chain/shared/cycle shapes; native conversion, computation, and export took
0.126/0.138/0.115 seconds, approximately 3.57×/4.12×/3.12× faster. These single-sample,
one-effect results establish useful native graph throughput, not a real-project speedup.

**Decision:** keep the backend opt-in. The Python API plus Rust-owned state architecture
works and passes differential verification, but this boundary does not yet justify a
default switch. A subsequent experiment should first reduce repeated Python owned-symbol
and direct-input preparation and inspect duplicate ownership with an allocation profiler.
Then repeat whole-check/RSS measurements with balanced run order. Expanding Rust scope,
switching defaults, or publishing wheels is not part of this PoC.

Latency samples did not overlap agent-run tests/builds. The native interning fix was
built during the Python unchanged-RSS phase, before the native process started; unrelated
machine pressure was not controlled. Earlier abandoned runs, including overlapping
validation and an orphaned child, are excluded from the accepted JSON. Stability
thresholds and sample counts were not relaxed in response to results.
