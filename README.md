# taut

`taut` makes hidden Python backend conventions explicit and blocks only violations it can
determine reliably. The same source and configuration always produce the same result. It does
not hard-code the names or directory layout of any company or service.

Version 0.2.0 adds authenticated cross-process analysis caching and a supervised incremental
daemon while preserving canonical CLI output. It supports Python 3.12 or newer on platforms
supported by Python:

```bash
uv add --dev pytaut==0.2.0
uv run taut check .
```

For a reproducible source checkout, use `uv add --dev "pytaut @ git+https://github.com/taewoo-dev/taut.git"`.

## Configuration

Define repository roles and allowed dependencies in `pyproject.toml`. Strict mode is enabled by
default. File length is a repository policy parameter rather than an engine hard limit.

```toml
[tool.taut]
schema_version = 3
packs = ["taut.backend"]
providers = ["taut.python-core", "taut.fastapi", "taut.pydantic", "taut.sqlalchemy"]
strict = true
source_roots = ["."]

[tool.taut.roles]
router = ["app/router/*.py", "app/router/**/*.py"]
service = ["app/service/*.py", "app/service/**/*.py"]

[tool.taut.allow]
router = ["router", "service"]
service = ["service"]

[tool.taut.zones]
test = ["tests/*.py", "tests/**/*.py"]

[tool.taut.transaction]
owner_roles = ["service"]
session_providers = ["app.database.get_async_session"]
```

Built-in policies cover external calls, databases, security, DTOs, and schemas. Add only the
repository-specific differences:

```toml
[tool.taut.external]
modules = ["company_sdk"]
wrappers = ["app.adapters.external_call"]

[tool.taut.enum]
shared_modules = ["app.core.enums"]
```

Rules can be scoped by zone, entrypoint roles can receive distinct effect allowances, and an
intentional exception can be approved for one exact symbol with a required reason:

```toml
[tool.taut.rule_zones]
IMPORT001 = ["prod", "migration", "script"]
IMPORT002 = ["prod", "migration", "script"]

[tool.taut.boundary_extensions.entry_allowed_kinds]
task = ["external"]

[tool.taut.layers]
scoped_construction = ["adapter"]
dependency_registration = ["composition"]

[[tool.taut.approvals]]
rule = "SESSION003"
symbol = "app.services.notifications._persist"
target = "sqlalchemy.ext.asyncio.AsyncSession"
kind = "participant"
zones = ["prod"]
reason = "called only inside the notification transaction"
```

`allow`, `entrypoint`, `factory`, `lazy_import`, and `security_wrapper` approve the matching
finding after normal rule evaluation. `participant` and `managed` are SESSION003 contracts:
a participant may use a caller-owned session but may not open, commit, or roll it back; a managed
function is an independently managed service entrypoint. Omitting `target` approves all targets
for that rule and symbol. Module-level findings use the module ID as `symbol`.

## Commands

```bash
taut config validate .
taut config explain .
taut config migrate .
taut check .
taut check . --verbose
taut check . --format json
taut check . --daemon auto
taut rules
taut rules ASYNC001
```

Normal CLI checks use the project-local `.taut_cache` by default. Repeated editor or local
development checks can use the resident analyzer with `--daemon auto`; CI should normally keep
the default `--daemon never` for process isolation. The daemon is scoped to one canonical project
root, exits after 30 minutes of inactivity, and can be managed explicitly:

```bash
taut daemon start .
taut daemon status .
taut daemon restart .
taut daemon stop .
taut cache stats .
taut cache clean .
```

Use `--no-cache` for a canonical cold run. Cache failures are treated as misses and never change
findings. See [`docs/performance.md`](docs/performance.md) for the measured contract and
[`docs/operations.md`](docs/operations.md) for lifecycle and security details.

To check another local repository:

```bash
uvx --no-cache --from /path/to/taut taut check /path/to/project
```

For a one-time audit that must not modify the target repository, provide an absolute path to an
external configuration file:

```bash
taut check /path/to/project --config /path/to/audit-policy.toml
```

Role patterns and `source_roots` are resolved relative to the target project, not the
configuration file. The `.policy/policy.toml` location and explicit external configuration files
remain supported. Configuration content uses schema v3; `taut config migrate` prints a v3
migration without changing the source unless an explicit output path is supplied.

## Results

The default terminal output prints one finding per line followed by the error and warning totals.
Long findings wrap to the next indented line. Non-terminal output uses a width of 120 characters;
override it with an option such as `--width 100`. Use `--verbose` only when you need related
locations, remediation guidance, decision counts, and the decision digest.

JSON report schema v3 includes resolved, unresolved, ambiguous, and dynamic call/reference counts;
resolved and unresolved imports; unavailable capabilities; skipped evaluations; and coverage gaps.
It reports used and unused symbol approvals separately from inline ignores. A rule runs only when
its declared semantic capabilities are present.

- Exit code `0`: no enforced violations
- Exit code `1`: one or more enforced violations
- Exit code `2`: invalid configuration, analysis failure, or an enforced rule that could not be
  evaluated

When an exception is unavoidable, suppress only the exact rule on the affected line:

```python
legacy_call()  # taut: ignore[ASYNC001]
```

An ignore without a rule ID, or with an unknown rule ID, is a configuration error. An ignore that
does not suppress a real violation is reported as `IGNORE001`. File-wide ignores, violation
baselines, and expiration management are intentionally unsupported.

Raw SQL is not generally allowed. Application code should use SQLAlchemy expressions. A necessary
raw query must pass through a registered shared wrapper configured with `raw_query_roles` and
`raw_query_wrappers`. Fixed Model `server_default` expressions and partial Index predicates are
allowed only within `schema_sql_roles` and `schema_sql_argument_names`.

Registered raw-query calls must provide `name`, `statement`, and `parameters` as explicit keyword
arguments. `name` and `statement` must be string literals, preventing SQL construction through
f-strings or string concatenation.

## Built-in rules

With the default `strict = true`, `CAT001` is advisory and the other 47 rules are enforced.
Individual rules cannot be disabled. Use `strict = false` before adoption to report every finding
as a warning.

| Group | Rules |
|---|---|
| Architecture | `ARCH000`-`002`, `BOUNDARY001`-`003`, `ENTRY001`, `SERVICE001`, `QUERY001`, `MODEL001`, `ADAPTER001`-`002`, `WIRING001`, `CONFIG001`, `DEPENDS001` |
| Runtime safety | `TIME001`, `ASYNC001`, `RUNTIME001`, `IMPORT001`, `IMPORT002`, `SIZE001`, `SEC001` |
| Database and transactions | `TX001`, `TX002`, `SESSION001`-`003`, `ORM001`, `ORM002`, `DB001`, `SQL001` |
| External calls | `HTTP001`, `LOG001`, `CAT001` |
| Data contracts | `DTO001`, `DTO002`, `SNAPSHOT001`, `SCHEMA001`-`003`, `API001`-`003`, `ENUM001`, `EXC001` |
| Test boundaries | `TEST001`, `TEST002` |
| Inline ignores | `IGNORE001` |

Each rule declares whether it applies to `prod`, `test`, `migration`, or `script` code. Missing
roles, dependency cycles, import placement, file size, dynamic execution, async safety, and
security access are checked in every zone. API, DTO, database, and service-boundary rules apply to
production code.

Resolution-state applicability follows the resolver facts, not source spelling. Conditional and
ambiguous references carry resolver candidates and can yield `indeterminate` when a configured
symbol is a candidate; unresolved and dynamic references do not identify a configured target, so
each group-C rule follows its matrix row (`evaluate`-compatible for rules that can continue,
`not_applicable` where no target exists). This preserves unrelated-uncertainty behavior and avoids
manufacturing relevance from written names.

The built-in backend pack contains all 48 rules. It consumes versioned semantic capabilities from
the built-in Python provider (`taut.syntax@1`, `taut.bindings@1`, `taut.imports@1`, and
`taut.uses@1`). Third-party integrations can use the public `taut.plugins.v1` and
`taut.semantic.v1` contracts without importing the concrete AST analyzer.

Fact providers are loaded through the `taut.fact_providers.v1` entry-point group. A provider
declares a stable `id`, numeric dotted `version`, `provides` capability specifications such as
`example.types@1`, and optional `requires` entries (`ProviderDependency`). Providers are composed
deterministically by dependency then `(id, version)` order. Each capability must have exactly one
owner; a provider that fails or returns a payload different from its declaration is isolated and
reported as unavailable with an actionable reason. Successful capabilities retain provider/version
provenance in the snapshot and JSON analysis coverage, so integrations can reproduce a decision.

When `taut.backend` is used without an explicit `providers` setting, configuration loads the
built-in providers in stable order: `taut.python-core`, `taut.fastapi`, `taut.pydantic`, and
`taut.sqlalchemy`. An explicit `providers` list is authoritative (for example, listing only
`taut.python-core` intentionally omits framework providers); provider IDs must be unique.

An unregistered call that might have an external effect cannot be proven unsafe, so it is reported
as a `CAT001` warning. After classifying the call, add it to the project effect catalog for precise
enforcement.

## Development

```bash
bash scripts/test.sh
bash scripts/test.sh --only tests/unit/policy/test_builtin_rules.py -x
```

The full check runs the repository's own policy rules, Ruff, mypy strict, Pyright strict, pytest
with at least 90% branch coverage, package builds, and an isolated wheel installation.

See [`MIGRATION.md`](MIGRATION.md) for the 0.1.x upgrade checklist and [`docs/VALIDATION_REPORT.md`](docs/VALIDATION_REPORT.md)
for reproducible release checks. See [`docs/README.md`](docs/README.md) for current design documents.
