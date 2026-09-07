# Anti-monitor follow-up — 2026-09-05

The analyzer passed the existing policy on a temporary snapshot containing 1,224 Python sources.
Both the baseline (`0dea529`) and follow-up reported zero diagnostics, assurance issues, and
engine issues. This establishes compatibility with this snapshot, not exhaustive runtime safety
or independently measured real-project precision/recall.

## Source and isolation

The snapshot captured the working tree, including existing uncommitted source changes, when HEAD
was `14bf0c5efddc286db6e4127f28917b5f772f96c7`. Source counts were app 584, tests 423,
alembic 216, and gunicorn 1. The manifest also includes the original policy configuration.
All 1,225 captured files matched the original at the preservation check. Original Git state
changed concurrently through other work; this task made no writes to the original checkout.
Experiments modified disposable copies only. No application, database, or application tests ran.
Foreign source and full diagnostic reports remain outside this repository.

## Controlled detection and resident parity

| Temporary change | Expected and observed result |
|---|---|
| Existing source | Exit 0 |
| Immediately invoke a lambda containing `time.sleep` in an async function | Exit 1, ASYNC001 |
| Pass `time.sleep` to a directly invoking synchronous helper from async code | Exit 1, ASYNC001 |
| Replace with `asyncio.to_thread(lambda: time.sleep(...))` | Exit 0 |
| Remove the injected file | Exit 0 |

Dangerous cases and the restored state matched fresh analysis byte-for-byte for stdout, stderr,
and exit status. These are deliberately injected regressions, not discovered application bugs.
The existing snapshot contains 310 lambdas but no immediately invoked lambda; it primarily
exercises compatibility with deferred callbacks and offloading. The final source was rechecked
after adding a guard against confusing nested expressions with direct callable arguments.

## Development performance observations

The existing daemon benchmark compared the baseline with the follow-up development source on
the same snapshot, using three timing repetitions and 30 unchanged checks for memory. Cold is
a single startup observation. Each version's timed output matched its own fresh-analysis oracle.
The after benchmark predates the final callable-argument shape guard; its source hash is retained
separately from the final verification hash in the [aggregate JSON](antimonitor-followup.json).

| Phase | Before seconds | After seconds |
|---|---:|---:|
| Cold | 12.690 | 14.342 |
| Unchanged, median | 0.554 | 0.338 |
| Ordinary edit, median | 2.058 | 2.599 |
| Shared edit, median | 5.043 | 5.209 |
| Restart, median | 12.495 | 14.736 |
| Concurrent clients, median | 1.051 | 0.982 |

The ordinary file was `alembic/env.py` (no transitive inbound modules), and the shared file was
`app/core/config.py` (650 transitive inbound modules). This shared-machine sample does not prove
a speedup or isolate regression causes. Ordinary/shared edit latency remains above the previous
2/4-second goals in this after sample; further profiling remains warranted.

The baseline memory sequence met the plateau criterion. The first after sequence did not:
RSS varied widely, so that failed classification is retained. A separate 30-check rerun matched
output throughout and met the same stability criterion: approximately 819 to 798 MiB, with the
last 15 samples identical. This supports short-run stability in the rerun, not a general absence
of leaks. Resident memory near 800 MiB remains a meaningful operational cost. Test daemons stopped.

## Remaining evidence gaps

General callback forwarding, methods/decorators, starred argument binding, and effects outside
the catalog remain incomplete. The selected synthetic corpus now detects all six labeled
violations with no findings on four safe controls, but those ten cases do not estimate production
accuracy. Independent labels, adoption effort, review-time benefit, broader performance samples,
and longer memory runs remain future work. No policy was weakened to obtain this passing result.
