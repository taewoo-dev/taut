# Detection scope, measurement, and adoption

This document describes the detection and adoption changes released in 0.10.0.
Configuration and report schemas remain v5; new report keys are additive.

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

Run the evaluator against the revision you intend to use and retain its JSON output\nwith that source revision. Results on selected synthetic cases are not estimates of\nreal-world detection accuracy.\n\n## Adopt rules incrementally

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
