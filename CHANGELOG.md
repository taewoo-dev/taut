# Changelog

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
