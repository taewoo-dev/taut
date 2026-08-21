# Changelog

## 0.2.0

- Added versioned plugin/semantic contracts, capability-gated packs, deterministic provider
  ordering, and isolated provider failures.
- Added schema v3 configuration, explicit provider-list semantics, JSON report v3, provenance,
  deterministic decision digests, and 0.1.x/v1/v2 migration.
- Added resolver-aware uncertainty: relevant missing or ambiguous facts become `INDETERMINATE`.
- Supported runtime is Python 3.12+; see [`MIGRATION.md`](MIGRATION.md).
