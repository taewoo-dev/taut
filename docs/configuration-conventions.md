# Stable configuration for growing projects

Configure responsibilities once, then add code inside those conventions. New files inherit
the same checks as existing files. Observing a new import or effect never grants permission.

The compact syntax and CLI additions below are source-tree features. Install a release
containing them before using new syntax in a consuming project's pinned dependency.

## Conventions during onboarding

`init` proposes directory and filename patterns and omits redundant defaults. It does not
generate per-file exclusions to conceal conflicting responsibilities. Move or split mixed
code, or explicitly review a stable narrower selector, then regenerate the proposal.

In `role_selectors` answers, supply a reason and optional integer `priority`. All selectors
for one role must have the same priority. Different roles tied at the highest priority fail.

```json
{
  "role_selectors": [
    {"role": "service", "include": ["app/services/*.py"], "reason": "Domain services"},
    {
      "role": "workflow",
      "include": ["app/services/workflows/*.py"],
      "priority": 10,
      "reason": "Workflow composition follows a separate boundary contract"
    }
  ]
}
```

This is an answers excerpt; retain the current version, digest, architecture, and feature
decisions. Roles have no implicit permissions: the reviewed allow graph and transaction
and boundary policies still apply. A priority selects a contract; it does not waive findings.
Taut does not special-case `_orchestration` or company-specific paths.

**Role/zone patterns use `fnmatchcase`: `*` crosses directory separators. Source `include`
and `force_include` use `Path.glob`: retain recursive discovery patterns.** Role
`app/services/*.py` covers nested services; source `app/*.py` does not discover them.
The default source scope already covers recursive Python files and stubs. Include `*.pyi`
in a role convention when the project owns stubs.

## Shared packages and reusable boundaries

```toml
[tool.taut.enum]
shared_modules = ["app.core.enums", "app.core.exceptions.error_code"]
```

The prefix matches a package and its descendants, not sibling names like `app.core.enums_extra`.
New enum modules need no registration. Replacing an existing exact-module list with a package
is a reviewed convention change that intentionally covers future modules; simplify does not
make that decision.

Configure session providers and common external-call wrappers/contexts once, then reuse them.
Keep exact approval targets exact. New ordinary files should not need registration; new trust
boundaries and intentional policy changes legitimately require configuration review.

## Compact policy declarations

```toml
[tool.taut.role_groups]
contracts = ["dto", "enum"]

[tool.taut.allow]
service = ["service", "@contracts"]
dto = ["dto", "enum"]
enum = ["enum"]

[[tool.taut.effects]]
symbols = ["app.clock.utc_now", "app.clock.today"]
effects = ["time.now"]
access = "approved_wrapper"
```

This is an excerpt: every named role must be declared. Groups are non-empty sets of declared
roles, referenced only in allow arrays. Expansion is a union, not transitive permission.
Nested or unknown groups fail. Inheritance resolves before expansion; child arrays replace
base arrays as usual. A group declaration alone grants nothing.

An effect entry accepts exactly one of `symbol` or a non-empty unique `symbols` array. Each
symbol receives the same effects/access contract. Conflicting entries and changes to built-in
effects remain errors. Existing schema 5 declarations retain their meaning.

## Read-only inspection and simplification

```bash
taut config explain backend --path app/services/orders.py
taut config explain backend --format json
taut config simplify backend
```

Explain shows expanded policy and declaring files for explicit values, including inheritance.
Unconfigured values come from built-in defaults. `--path` accepts a project-relative or
absolute path inside the selected member. It reports matching selectors, winning priority,
allowed imports, and actual source discovery scope. It does not analyze the file's behavior.
Missing, excluded, or unclassified paths return exit 2; classified in-scope files return 0.
Use check to validate code.

Simplify prints a standalone `[tool.taut]` snippet without writing files. It flattens explicit
inheritance, removes values equal to effective defaults and provably redundant role/zone
patterns, and groups identical effects. It preserves discovery scope and verifies semantic
equivalence after rendering and reparsing. It does not infer architecture, approve effects,
consolidate enum prefixes, or rewrite code. Formatting is normalized and source comments are
omitted from the proposal; original files remain untouched. Review their comment-based
rationale before adopting the snippet. Structured reasons are retained.

Select individual workspace members for simplify or explain --path. Check/explain still read
legacy standalone normalized configurations; simplify accepts the `[tool.taut]` format.

## Existing-project migration

1. Fix intended role, import, and transaction contracts before considering findings.
2. Use audit/check and path inspection to identify misplaced or mixed responsibilities.
3. Move or split code to satisfy the contracts, updating callers and behavior tests.
4. Replace obsolete per-file registration with reviewed directory conventions.
5. Verify that new compliant files need no config changes and new violations still fail.

Do not preserve a workaround merely to reproduce an old green result. Syntax simplification
requires equivalence; policy-conformance migration can reveal additional violations.
