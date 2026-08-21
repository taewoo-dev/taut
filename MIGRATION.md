# Migrating to pytaut 0.2.0

Version 0.2.0 requires Python 3.12+ and configuration schema v3. The legacy
`.policy/policy.toml` location remains supported, but 0.1.x/v1/v2 configurations must be
migrated before validation:

```bash
taut config migrate . --output migrated-policy.toml
taut config validate . --config migrated-policy.toml
taut check . --config migrated-policy.toml --format json > report-v3.json
```

Migration does not modify the source unless `--output` is supplied. It upgrades the schema, adds
the `taut.backend` pack, and adds built-in providers when the old configuration omitted them.
Review the generated file and stale fields; validation reports `schema_version must be 3` for an
unmigrated file and rejects unknown configuration fields.

With `taut.backend`, an omitted `providers` key uses the stable defaults:

```toml
providers = ["taut.python-core", "taut.fastapi", "taut.pydantic", "taut.sqlalchemy"]
```

An explicit list is authoritative: `providers = ["taut.python-core"]` intentionally disables
framework providers and does not merge with defaults. Third-party providers use
`taut.fact_providers.v1`, rule packs use `taut.rule_packs.v1`, and integrations should target the
public `taut.plugins.v1` and `taut.semantic.v1` contracts.

JSON output is report schema v3. `INDETERMINATE` means a safe judgment was impossible because a
required capability/fact/stage is missing or a relevant resolution candidate is uncertain; it is
not proof of a violation. In strict mode an enforced indeterminate evaluation exits with code 2.

For rollback, restore the 0.1.x lockfile/configuration and install `pytaut==0.1.*` in a separate
environment. Keep the migrated config and v3 report for comparison until CI results are accepted.
