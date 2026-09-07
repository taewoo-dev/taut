# Detection scope, measurement, and adoption

This document describes unreleased changes on top of 0.9.0. They require a source installation
until a new package is published. Configuration and report schemas remain v5; new report keys
are additive.

## What a successful check establishes

Exit 0 means no enforced violation or blocking analysis/configuration issue was reported within
the supported analysis and configured policy. Advisory findings may still exist. It is not a
proof of runtime safety or exhaustive detection.

| Report field | Meaning | Does not establish |
|---|---|---|
| `assurance.complete` | Declared source/feature assurance checks have no issues | All runtime behaviors have been modeled |
| `coverage.analysis.calls.resolved` | Call symbol identity was resolved | Argument-dependent effects were proven |
| `coverage.gaps = []` | No rule emitted a coverage gap | No unmodeled semantics exist |
| `coverage.rule_levels` | Effective enforced/advisory levels | All rules are enforced |
| `interpretation` | Machine-readable statement of these scope limits | An additional safety analysis |

Text output says "no policy violations within supported scope" on an empty successful check. Non-resolved call
counts are visible even in compact output; verbose output explains scope and lists advisory rules.
Assurance failures and indeterminate enforced checks no longer produce a green success summary.

## Supported improvements and remaining limits

Selected synchronous operations on `pathlib.Path`, `PosixPath`, `WindowsPath`, Requests sessions,
and `builtins.open` now participate in the effect catalog. Exact known constructor chains such as
`Path("data").read_text()` resolve without guessing that every capitalized name is a constructor.
Project-owned lookalikes and shadowed builtins are not matched merely by spelling.

Known catalog effects supplied to directly invoked parameters of undecorated module-level
synchronous functions can now produce definite effects when the parameter call has no guard or
context-manager boundary and the argument binding is valid. Positional, keyword-only,
positional-only, and default arguments are supported. Guarded or context-managed invocations
remain `callback_effect` uncertainty. Attribute arguments must resolve to one symbol chain;
merely containing a catalog symbol inside an expression is insufficient.

Known callback effects also propagate through multiple undecorated synchronous helpers,
including helpers in other modules. Parameter-to-parameter forwarding reuses the same argument
binding checks. Invocation sets converge to a fixed point; a recursive forwarding cycle with
no callback invocation does not manufacture an effect. A guard or context boundary anywhere
on a forwarding path prevents that path from establishing definite synchronous execution.
Reassigned parameters, callable storage, and thread-offload calls do not establish forwarding.

Immediately invoked and locally assigned lambdas now have function facts and resolved call
identities. Their effects propagate only through actual calls. Storing a lambda, returning an
uninvoked lambda, `asyncio.to_thread(lambda: ...)`, and `run_in_executor(None, lambda: ...)` do
not inherit those effects merely because a lambda exists. A lambda parameter can itself be a
known callback. Default argument expressions still execute when the lambda is created.

These improvements are bounded. Method/decorator-based callback dispatch, starred argument
binding, arbitrary higher-order transformations beyond exact parameter forwarding, reassigned parameters, and
effects outside the catalog are not exhaustively modeled. Passing a first-party callable as an
argument does not automatically specialize its effect summary. These limitations can still yield
exit 0, and the small labeled corpus does not exhaust these cases.

Effect checks use dependent-module invalidation. A resident check after editing a callback
invoker is tested against a fresh check in both directions: safe to a definite violation and back to safe.

## Reproduce a labeled detection measurement

```sh
uv run --locked python scripts/evaluate_detection.py tests/fixtures/detection/async.json
```

The evaluator parses snippets in temporary projects and never executes their source. Labels must
include a reviewer, unique case IDs, known rule IDs, and reasons. Invalid analysis prevents a score
from being emitted. The measurement evaluates one named rule per snippet under service-role
defaults; it does not measure project assurance, framework integration breadth, adoption time,
or full-application correctness.

- Precision is definite true positives divided by all definite positive findings.
- Recall is definite true positives divided by all labeled violations. A violation reported only
  as indeterminate remains a false negative for this metric.
- Positive flag rate additionally counts indeterminate labeled violations. It must not be
  advertised as recall or proven detection.
- Indeterminate safe cases are reported separately, rather than counted as true negatives.
- Undefined ratios are JSON `null`, not a fabricated perfect score.

The checked-in corpus is synthetic and hand-labeled during repository review. It intentionally
contains known misses and safe controls. Small-corpus scores are regression evidence, not an
estimate of real-world precision or recall. Preserve missed cases when changing the analyzer.

### Measured comparison — 2026-09-05

The same 10 cases (6 violations, 4 safe controls) were evaluated with the current evaluator against
baseline commit `bfddf85` and the changed working tree, using Python 3.14.0. The old source was
extracted with `git archive` into a temporary directory and selected via `PYTHONPATH`, so the
baseline was executed rather than inferred from historical notes.

| Outcome | Baseline | Changed source |
|---|---:|---:|
| Definite findings on the 6 violations | 2 | 4 |
| Indeterminate on the 6 violations | 0 | 1 |
| No finding or uncertainty on the 6 violations | 4 | 1 |
| False findings / indeterminate on 4 safe controls | 0 / 0 | 0 / 0 |
| Definite-detection recall on this corpus | 33.3% | 66.7% |

At that first improvement point, immediate lambda invocation remained a silent miss and the
callback was indeterminate rather than a definite finding. Original case outcomes and source hashes
are retained in [baseline JSON](quality/async-before.json) and [changed-source JSON](quality/async-after.json).

A development performance sample used 32 synthetic mixed FastAPI/SQLAlchemy/Pydantic modules,
three independent cold runs each. Median wall time was approximately 0.060 s before and 0.054 s
after, with deterministic digests within each version and no analysis/engine issues. This small,
non-isolated sample does not establish a speedup, large-project latency, or daemon memory behavior.
Raw samples: [before](quality/performance-before.json), [after](quality/performance-after.json).

### Follow-up after commit 0dea529

The same 10 snippets now produce six definite findings on the six labeled violations and no
findings/indeterminate decisions on the four safe controls. The previously missed lambda and
uncertain direct callback are both detected. This is a regression result on selected examples,
not a claim of complete Python analysis. [Follow-up results](quality/async-followup.json).

Real-project validation uses a temporary snapshot of the current anti-monitor backend, including
its existing uncommitted source changes. Raw source and full analysis reports stay outside this
repository. See [the real-project report](quality/antimonitor-followup.md) for source identity,
controlled probes, resident parity, timing, memory, and limitations.

## Adopt rules incrementally

Keep `strict = true` and stage explicitly selected rules as advisory:

```toml
[tool.taut.rules]
ASYNC001 = "advisory"
```

The selected rule continues to run and its findings remain visible. Its indeterminate decisions
are also advisory. All other rule levels and strict source/feature assurance remain active.
Remove the entry to restore the rule's declared default. `off`, unknown rules, and promotion of
advisory-only rules such as `CAT001` are rejected. `strict = false` still downgrades all findings
and does not enforce assurance; it has different semantics from selectively staging a rule.

`config explain` exposes the effective policy, `config simplify` preserves staged levels, and
configuration changes invalidate resident state. Record the reason and intended review date in
the team's policy review; staging should not be confused with a compliant codebase.

## Measure actual team value

For each consenting pilot project, retain the source revision, policy digest, engine revision,
and reviewer identity. Use the same declared policy and scope for before/after comparisons.

| Evidence | How to collect it |
|---|---|
| Setup effort | Active human minutes from init to reviewed, complete audit; separate waiting time |
| Diagnostic usefulness | Review a recorded sample as valid violation, false positive, or undecided; include reasons |
| Misses | Independently label violations and safe examples before running the tool; include missed cases |
| Maintenance cost | Track policy edits and active review minutes over add/move/rename workflows |
| Review benefit | Compare similar changes' review time and repeated convention comments; disclose confounders |
| Runtime cost | Measure cold/edit latency and resident memory with the existing benchmark script |

Do not infer team value from diagnostic count, test coverage, or an all-green audit. No new
external-project adoption measurements were collected in this change. Such evidence requires
real project owners and reviewers; the synthetic evaluator is the reproducible starting point.

## Internal boundaries

Framework-specific database facts are translated by `analysis/framework_operations.py` into
`domain.database_operations.DatabaseOperation`. Shared policy context and atomicity summaries
consume those operations rather than Tortoise fact classes. The existing Tortoise diagnostic
identities are retained. Internal consumers of `PolicyContext.tortoise_queries`/`tortoise_query`
should use `database_operations.queries`/`database_query`; the old helpers were not retained.

The independent AST convention checker reads the dependency allow graph from `pyproject.toml`.
It retains its own checking implementation without a second hard-coded graph to maintain.

The resident check service now separates analysis-request construction, cache setup, policy
execution, and report assembly. Its orchestration method shrank from 208 to 78 lines; persistent
module-cache handling lives in `cache/module_results.py`. The same resident/cold integration and
installed-wheel checks cover the refactoring.
