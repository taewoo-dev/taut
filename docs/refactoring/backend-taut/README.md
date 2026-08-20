# 0.2.0 uncertainty migration audit

`uncertainty-migration-matrix.json` is the complete, machine-checkable audit of
the built-in backend registry. The registry is exactly 48 IDs; the contract test
requires a one-to-one ID match, unique matrix rows, valid state/verdict values,
and disjoint implementation groups.

The engine already maps missing capabilities, incomplete projects, and
insufficient stages to `INDETERMINATE`. That is the required migration behavior
for every rule. A rule that does not consume a symbol reference has
`resolution_input: none`: resolution states are not evidence for PASS or FAIL,
so the matrix records them as `not_applicable` rather than inventing a verdict.
Call rules consume either the call reference or effect resolution. `CAT001` and
the session rules intentionally gate on a resolved provider and therefore map
uncertain references to `NOT_APPLICABLE`; `ASYNC001` currently gates on the
effect catalog and does the same for unknown effects. `TIME001` and `TX001`
retain explicit `INDETERMINATE` only when a written-name/receiver heuristic
suggests the call may be relevant; group D replaces those heuristics with
provider capabilities.

## Heuristic and provider follow-up

The current suffix heuristics are `now`, `today`, `utcnow`, `commit`, and
`rollback`; TX001 also guesses database ownership from receiver names. The
preferred provider capabilities are typed effect facts for time and transaction
operations, resolved session-provider identities, external-call timeout/logging
facts, and framework-backed route/schema/model metadata. Missing capability or
project completeness must remain `INDETERMINATE`, never PASS.

Groups are disjoint: A is the module-only baseline, B is call/effect resolution,
C is project/completeness-sensitive, and D removes heuristics after B/C. Group B
and C depend on A; D depends on both B and C. This commit changes no evaluator
semantics.
