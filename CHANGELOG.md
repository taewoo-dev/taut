# Changelog

## 0.6.0

### Isolated workspace orchestration

- Added an explicit `[tool.taut.workspace]` manifest that runs each member with its own policy,
  import roots, cache, and analysis graph while aggregating root `check`, `audit`, and config output.
- Added generic init discovery for repositories containing multiple independent Python projects;
  combined root policies are refused and the workspace manifest is written only after member setup.
- Added explicit `[tool.taut] extend` inheritance with deterministic table overrides, array
  replacement, missing-file validation, and cycle rejection instead of implicit cascading.

### Proof-oriented onboarding

- Added init contract v6 with reviewed glob role selectors, exact exceptions, and blocking grouped
  questions for every low-confidence role instead of silently accepting `application`.
- Split safe observed import acceptance from individually reasoned risky-edge allow/deny decisions.
- Unified Python source inventory and exclusive test/migration/script path precedence across init
  and strict assurance, and preflight-audited generated policy before allowing a write.
- Replaced repeated text scans with one parsed source observation pass and semantic feature checks.
- Made repository-noise exclusions an engine-owned baseline and connected reasoned
  `[[tool.taut.exclusions]]` entries directly to source discovery, so generated configuration no
  longer repeats cache, VCS, build, virtual-environment, and dependency-directory patterns.

### Provider precision and extensibility

- Limited provider uncertainty to rule-relevant symbols and removed provider dependencies from
  rules that consume only core semantic facts, preventing unrelated module-wide exit-code-2 fanout.
- Preserved definite findings alongside target-local coverage gaps for public API field metadata.
- Allowed an approved external-call wrapper to be either the callable that owns the call or an
  enclosing context manager, covering centralized HTTP client methods without weakening LOG001.
- Added the public `OnboardingContributorV1` contract and
  `taut.onboarding_contributors.v1` entry point for third-party framework/provider discovery.

## 0.5.0

### Explicit cross-project contracts

- Separated class-level DTO, Request, Response, Enum, Exception, and Snapshot contracts from
  module architecture roles.
- Added one configurable Response mapper name while retaining strict typed-classmethod and
  explicit-field mapping requirements; bulk object/dict transfer remains rejected.
- Extended immutable DTO enforcement to Pydantic `ConfigDict(frozen=True)` models and configured
  first-party DTO bases.
- Made exception constructor/field code names configurable and scoped duplicate class names to
  their configured exception family while keeping public error-code uniqueness global.

### Framework and transaction precision

- Added `taut.pytest.fixtures@1` provenance and fixture-dependency facts so raw HTTP test-client
  exceptions require a proven approved fixture origin.
- Propagated Tortoise QuerySet identity through statically resolved first-party return values.
- Added `TX003` for multiple writes outside a proven transaction context or decorator, including
  capped interprocedural write summaries and relevant uncertainty propagation.
- Added static mapping-key summaries for endpoint documentation helpers without executing project
  code.

### Auditable onboarding and assurance

- Added schema/report/init v5, exact activation-symbol liveness and local kind checks, response
  mapper discovery, and transaction decorator configuration.
- Added a mandatory review of observed file-size recommendations or explicit project/role limits;
  init no longer hides the default size budget.
- Bumped the Python AST adapter identity and Tortoise provider version to prevent stale cache reuse
  across changed semantic facts.

## 0.4.0

### Tortoise ORM support

- Added the built-in `taut.tortoise` semantic provider for models, fields, relationships,
  connections, transactions, queries, and raw SQL.
- Connected Tortoise facts to database assurance, layer and query boundaries, transaction
  ownership, and raw-SQL enforcement without relying on receiver variable names.
- Added optional `transaction.provider_item_types` mappings for project-owned transaction
  wrappers while preserving SQLAlchemy wrapper compatibility.
- Added public plugin exports, onboarding detection/defaults, contract tests, and user guidance.

### Reviewable role onboarding

- Added exact singular/plural directory aliases for conventional backend roles without unsafe
  automatic word singularization.
- Added role observations with candidates, evidence, confidence, and explicit conflict state to
  the init JSON v4 contract.
- Added exact-path `roles` overrides and custom-directory `role_aliases` answers; conflicting
  evidence now blocks writes until an exact role decision is supplied.
- Added semantic corroboration for FastAPI routers, Pydantic schemas, and Tortoise models, while
  keeping low-confidence application fallback visible for review.
- Stopped treating comments containing `Snapshot` as snapshot-policy evidence.

### Package-aware source onboarding

- Added generic source-root evidence for uv workspaces, Hatch, setuptools, Poetry, PDM, and
  conventional `src` layouts to the init JSON v4 contract.
- Added explicit source-scope acceptance and `source_roots` overrides; missing or contradictory
  package metadata blocks automatic acceptance instead of being guessed.
- Included the packaging manifests used by discovery in the project digest so stale source-scope
  answers are rejected after workspace or build configuration changes.
- Made overlapping source roots deterministic: each Python file is analyzed once relative to its
  most specific root, while genuine duplicate module identities still fail discovery.

### Complete machine-readable onboarding decisions

- Versioned both proposals and answers at init schema v4 and reject missing or mismatched answer
  versions with regeneration guidance.
- Added validated answers for zones, reasoned exclusions, schema and exception symbols, enum
  modules, transaction providers, and external-call logging wrappers.
- Required activation details before writing policies for required schema, exception, enum,
  transaction, and external-call features instead of deferring predictable inactive-policy errors.
- Proposed only semantic providers supported by real import statements and centralized module ID,
  relative-import, and internal-import resolution across init and check.
- Expanded source-module conflict diagnostics with both paths and the source root used for each.

## 0.3.0

### Complete project assurance

- Added schema v4 feature expectations, reasoned source exclusions, exact not-applicable
  assertions, and approval/inline-ignore budgets.
- Strict checks now fail trust with exit code 2 when Python sources, architecture roles,
  selectors, or required backend policy surfaces are missing or inactive.
- Added structured assurance data to deterministic JSON report schema v4.

### AI-safe onboarding and extensions

- Added read-only `taut init` proposals with project digests, explicit machine-readable questions,
  stale-answer rejection, and atomic opt-in writes that never replace an existing configuration.
- Added `taut audit`, `taut config schema --format json`, and JSON rule discovery for automated
  setup and remediation loops.
- Strict third-party packs now require a versioned assurance auditor covering every registered
  rule; auditor identity participates in decision and cache compatibility.

### Verification and migration

- Added source-preserving v1-v3 to v4 migration and actionable assurance remediation output.
- Validated all three `medisolveai-auth` backends with no diagnostics, assurance issues, engine
  issues, skipped rules, or coverage gaps under reviewed temporary schema-v4 policies.
- Passed 1,141 tests at 90.15% branch coverage plus Ruff, mypy, Pyright, package builds, and an
  isolated installed-wheel smoke test.

## 0.2.1

### Policy precision and configuration

- Added reasoned, symbol-scoped approvals with zone scoping, used/unused approval audits, and
  deterministic inclusion in policy decision digests.
- Added per-rule zone configuration and role-specific file-size limits.
- Fixed session-rule unresolved-call fan-out so uncertainty remains local to relevant candidates
  instead of spreading across unrelated calls in a module.

### Runtime and extension hardening

- Hardened authenticated cache reports and daemon request handling, including safer runtime-state
  ownership and failure isolation.
- Stabilized Python semantic identity and conditional binding behavior for incremental providers.
- Expanded the public plugin API and documented third-party rule-pack integration.

### Verification and compatibility

- Added CI and release verification on Python 3.12, 3.13, and 3.14.
- Added isolated wheel installation and end-to-end smoke checks to the release test script.
- Validated strict analysis against the anti-monitor backend with zero active findings,
  indeterminate findings, engine issues, or unused approvals.

## 0.2.0

### Semantic analysis and contracts

- Added versioned plugin/semantic contracts, capability-gated packs, deterministic provider
  ordering, and isolated provider failures.
- Added schema v3 configuration, explicit provider-list semantics, JSON report v3, provenance,
  deterministic decision digests, and 0.1.x/v1/v2 migration.
- Added resolver-aware uncertainty: relevant missing or ambiguous facts become `INDETERMINATE`.
- Supported runtime is Python 3.12+; see [`MIGRATION.md`](MIGRATION.md).

### Persistent incremental cache

- Added persistent report and module-analysis caches with bulk SQLite operations and deterministic
  cache keys that include project, configuration, adapter, resolver, source, and module identity.
- Added an authenticated project bundle for fast cross-process reuse. Payloads are HMAC-bound to
  their context and Python version, decoded through a closed domain-type allowlist, and treated as
  misses on any validation failure.
- Added incremental source hashing so unchanged projects reuse all modules and one-file edits
  reparse only the changed module while retaining exact no-cache output parity.
- On the anti-monitor validation checkout, measured about 10 seconds cold, 0.2 seconds unchanged,
  and 6.9–7.8 seconds for repeated single-file disk-cache edits.

### Resident daemon

- Added a supervised, per-project incremental daemon with authenticated localhost requests,
  concurrent-client serialization, safe lifecycle management, automatic idle shutdown, and exact
  output parity with the canonical non-daemon pipeline.
- Added dependency-aware resident invalidation for unchanged, ordinary-file, and shared-base
  edits, with reusable module, provider, and policy-evaluation state.
- Added a reproducible benchmark that performs a real content change for every edit sample,
  selects targets by transitive import impact, checks canonical output parity, and records daemon
  RSS over repeated checks.
- On the 952-module anti-monitor validation checkout, measured 0.189 seconds for an unchanged
  resident check, 1.321 seconds for an ordinary edit, and 2.723 seconds for a shared edit
  affecting 610 transitive importers.
