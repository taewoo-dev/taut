# 0.2.0 uncertainty migration audit

uncertainty-migration-matrix.json is the complete machine-checkable audit of all 48 built-in rules. Every row records its source module, evaluator class/function, semantic facts, resolution source, explicit policy for all five states, missing-data behavior, code evidence, required change, heuristic/provider migration, and implementation group.

Only IMPORT001, SIZE001, and TEST001 are marked syntax_only; they retain an all-NOT_APPLICABLE resolution policy. Rules with resolver-owned candidates (including EXC001) propagate relevant conditional/ambiguous candidates to INDETERMINATE, while unresolved/dynamic references without candidates remain compatible evaluation or NOT_APPLICABLE according to each row. ADAPTER002 and ARCH000 consume analyzer/manifest facts without confidence-bearing SymbolRefs, so all five resolution states are explicitly evaluate; incomplete or missing required facts still map to INDETERMINATE.

Missing capabilities, incomplete projects, insufficient stages, and missing required facts all map to INDETERMINATE. Current heuristic inventory includes TIME001 suffixes now/today/utcnow, TX001 suffixes commit/rollback plus receiver-name guessing, and legacy gating in effect/provider consumers; the target is typed provider facts with completeness and confidence.

Groups are file-disjoint: A API/model/enum/ignore, B architecture/boundaries, C construction/conventions/tests/classification/exceptions/external/security, and D persistence/runtime/session/effect providers. They contain 11/11/12/14 rules and depend A -> B -> C -> D. This correction documents observability limits rather than fabricating confidence or using source spelling heuristics.
