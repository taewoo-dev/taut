# 0.2.0 uncertainty migration audit

uncertainty-migration-matrix.json is the complete machine-checkable audit of all 48 built-in rules. Every row records its source module, evaluator class/function, semantic facts, resolution source, explicit policy for all five states, missing-data behavior, code evidence, required change, heuristic/provider migration, and implementation group.

Only IMPORT001, SIZE001, and TEST001 are marked syntax_only; they retain an all-NOT_APPLICABLE resolution policy. Rules with resolver-owned candidates propagate only relevant conditional/ambiguous candidates to INDETERMINATE; unresolved/dynamic references without candidates remain compatible evaluation or NOT_APPLICABLE according to each row. Group D module rules consume no resolution-bearing fact and evaluate all states, while call/effect rules propagate candidate uncertainty; incomplete or missing required facts still map to INDETERMINATE.

Missing capabilities, incomplete projects, insufficient stages, and missing required facts all map to INDETERMINATE. TIME001 and TX001 now consume only resolver-owned effect catalog entries; unresolved references are compatible evaluation unless the resolver preserves a relevant candidate. Group D module rules likewise propagate module completeness and never infer semantic identity from written source spelling.

Groups are file-disjoint: A API/model/enum/ignore, B architecture/boundaries, C construction/conventions/tests/classification/exceptions/external/security, and D persistence/runtime/session/effect providers. They contain 11/11/12/14 rules and depend A -> B -> C -> D. This correction documents observability limits rather than fabricating confidence or using source spelling heuristics.
