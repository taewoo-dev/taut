# Migrating to pytaut 0.3.0

Version 0.3.0 requires Python 3.12+ and configuration schema v4. The legacy
`.policy/policy.toml` location remains supported, but v1-v3 configurations must be migrated before
validation:

```bash
taut config migrate . --output migrated-policy.toml
taut config validate . --config migrated-policy.toml
taut audit . --config migrated-policy.toml --format json > assurance-v4.json
taut check . --config migrated-policy.toml --format json > report-v4.json
```

Migration does not modify the source unless `--output` is supplied. It upgrades the schema, adds
the `taut.backend` pack and built-in providers when omitted, and creates every assurance feature
decision as `absent`. This is intentionally conservative: `taut audit` reports every detected
feature that must be reviewed and changed to `required`.

Strict schema v4 requires an explicit decision for all built-in feature domains. A required feature
must have both code evidence and active policy setup. Every Python source must also be analyzed or
matched by a reasoned `[[tool.taut.exclusions]]` entry. Existing unreasoned `exclude` patterns
remain valid for discovery but fail strict assurance when they leave Python files unaccounted for.

With `taut.backend`, an omitted `providers` key uses the stable defaults:

```toml
providers = ["taut.python-core", "taut.fastapi", "taut.pydantic", "taut.sqlalchemy"]
```

An explicit list is authoritative. Strict third-party rule packs must now expose an
`AssuranceAuditorV1` that covers every rule in the pack; non-strict adoption remains available
while a plugin adds that contract.

JSON output uses report schema v4 and includes the structured `assurance` object. Exit code `2`
now also means strict assurance is incomplete. `INDETERMINATE` retains its earlier meaning: a safe
judgment was impossible because a required capability, fact, stage, or resolution candidate was
unavailable.

For rollback, restore the 0.2.1 lockfile and schema-v3 configuration and install `pytaut==0.2.1`
in a separate environment. Keep the v4 configuration and reports for comparison until the new CI
result is accepted.
