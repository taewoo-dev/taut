# taut

`taut` makes hidden Python backend conventions explicit and blocks only violations it can
determine reliably. The same source and configuration always produce the same result. It does
not hard-code the names or directory layout of any company or service.

Version 0.7.0 follows first-party helper calls when enforcing effects and transaction safety,
audits semantic role and workspace coverage, and reduces configuration-only failures without
weakening definite findings. It supports Python 3.12 or newer:

```bash
uv add --dev pytaut==0.7.0
```

For a reproducible source install, use a release tag or full commit SHA instead of the default Git
branch.

## Multiple independent Python projects

Keep one Taut policy and one analysis graph per independently packaged Python application. A
repository with `backend/pyproject.toml` and `ai/pyproject.toml` should declare a root workspace
instead of combining both applications under one `source_roots` list:

```toml
[tool.taut.workspace]
schema_version = 1
members = ["backend", "ai"]
```

Run `taut config validate .`, `taut audit .`, and `taut check .` once at the root. Taut executes
every member using its own configuration, import roots, cache, and analysis graph, then aggregates
the results. Exit code `2` takes precedence over `1`, which takes precedence over `0`. JSON output
contains one complete report per member. Run `taut check backend` to select one member directly.

When a root without Python project metadata contains multiple nested Python projects, `taut init .`
does not guess a combined architecture. It lists the members and asks you to initialize each first.
After every member has `[tool.taut]`, rerun `taut init . --write` to write the root workspace
declaration atomically.

Shared defaults require explicit inheritance; configurations never cascade implicitly:

```toml
[tool.taut]
extend = "../taut-base.toml"
```

The extended file must contain `[tool.taut]`. Nested tables are merged, child values override base
values, and arrays are replaced. Missing files and inheritance cycles are configuration errors.
Workspace roots cannot also contain project-policy keys, so member graphs cannot be merged by
accident.

## Start a new project

For conventions that keep working as files are added, policy groups, and read-only
`taut config simplify` / `taut config explain --path`, see
[stable configuration](docs/configuration-conventions.md).

`taut init` does not produce a finished policy automatically. It observes the repository and
creates a safe starting proposal. An AI or developer confirms the high-level decisions, writes the
proposal, completes repository-specific settings, and proves the result with `audit`.

### 1. Generate a proposal

```bash
uv run taut init . --format json > taut-init.json || test "$?" -eq 2
```

Taut does not modify the project in this step. The shell redirection (`>`) creates
`taut-init.json`. Exit code `2` is expected while questions remain; the JSON proposal is still
valid. Its v6 JSON contains detected Python files and features, package-aware source-root evidence,
per-file role candidates, confidence and conflicts, questions, proposed TOML, and a
`project_digest`.

The digest covers discovered Python file paths and contents plus the `pyproject.toml` manifests
used to discover a project or workspace. It does not cover README files, frontend files, lockfiles,
or unrelated settings. Python or relevant packaging-metadata changes invalidate earlier answers.

### 2. Answer the supported decisions

Create `taut-init-answers.json` from the proposal. Copy its schema version and digest, then review
source scope, import architecture, all 13 feature expectations, exact roles, zones, reasoned
exclusions, and the repository-specific symbols that activate required policies:

```json
{
  "schema_version": 6,
  "project_digest": "copy from taut-init.json",
  "architecture": {
    "accept_safe_observed_edges": true,
    "risky_edges": [
      {
        "source": "service",
        "target": "router",
        "decision": "deny",
        "reason": "services must not depend on delivery adapters"
      }
    ]
  },
  "accept_observed_source_scope": true,
  "size": {
    "accept_observed": true
  },
  "roles": {
    "app/services/payment_client.py": "adapter"
  },
  "role_aliases": {
    "usecases": "service"
  },
  "role_selectors": [
    {
      "role": "application",
      "include": ["app/use_cases/*.py", "app/use_cases/**/*.py"],
      "exclude": ["app/use_cases/legacy.py"],
      "reason": "application orchestration package"
    }
  ],
  "zones": {
    "test": ["tests/**"]
  },
  "exclusions": [
    {
      "patterns": ["generated/**"],
      "reason": "generated from the versioned API contract"
    }
  ],
  "policy": {
    "transaction": {
      "owner_roles": ["service"],
      "session_providers": ["app.db.transaction"]
    },
    "external": {
      "logged_calls": ["company_sdk.Client.send"],
      "wrappers": ["app.adapters.logged_call"]
    }
  },
  "features": {
    "api": "required",
    "schema": "required",
    "dto": "required",
    "snapshot": "absent",
    "exception_registry": "required",
    "enum": "required",
    "database": "required",
    "transaction": "required",
    "external_calls": "required",
    "security": "required",
    "tests": "required",
    "migrations": "required",
    "scripts": "absent"
  }
}
```

Answers without the current `schema_version` are rejected with an instruction to regenerate them;
this prevents an older AI prompt or cached answers file from silently using a changed contract.

Accept `recommended_source_roots` only after reviewing their evidence. To replace the recommendation
instead, omit `accept_observed_source_scope` and provide an explicit, project-relative list such as
`"source_roots": [".", "packages/orders/src"]`. Every discovered Python file must remain covered.
Taut recognizes uv workspace members and standard Hatch, setuptools, Poetry, PDM, and `src` layout
metadata; it does not contain repository-specific package names.

Use `required` only when that capability belongs in this repository, and `absent` only when it
must not exist. Do not use `absent` to hide configuration work.

`roles` keys must exactly match discovered Python paths. Prefer stable conventions for ordinary files.
`role_selectors` are reasoned include/exclude globs for a verified directory convention; selectors
that match nothing or tie at the highest `priority` are rejected. Init does not generate per-file
exclusions to hide mixed responsibilities; move or split the code. `role_aliases` maps one exact custom directory
name to a role and cannot redefine a built-in alias. Taut never guesses singular forms by stripping
`s`. Generated TOML preserves reviewed selector reasons as comments.

Accepting safe observed edges does not approve risky edges. Imports into delivery, bootstrap,
test/migration/script roles, cycles, and ambiguous `application` edges each require an `allow` or
`deny` decision with a non-empty reason.
Init preserves each reviewed risky-edge decision and reason as a comment beside the generated
allow graph so the rationale survives the answers step.

The `policy` object accepts validated `code_conventions`, `transaction`, `external`, and `enum`
settings. If schema, exception registry, enum, transaction, or external calls are `required`, Taut
refuses to write until their activation values are present. It never invents project-owned symbols.

The proposed size budget uses the observed per-role 95th percentile with headroom and a minimum
floor. Review it explicitly with `"size": {"accept_observed": true}` or provide
`default_max_lines` plus optional `role_max_lines`. This is an initial growth guard, not permission
to preserve an oversized outlier indefinitely.

### 3. Write the starting configuration

```bash
uv run taut init . --answers taut-init-answers.json --write
```

Writing is refused when answers are incomplete, source or role evidence still conflicts, the
project digest is stale, or an in-memory preflight audit finds an unclassified source, stale
selector, missing provider, false feature decision, or inactive policy. Taut writes through a
temporary file and atomic replacement. If `[tool.taut]` or
`.policy/policy.toml` already exists, `init` stops even in preview mode and directs you to
`taut audit` or `taut config migrate`.

### 4. Complete repository-specific settings

Review the generated `pyproject.toml`. In particular, verify that the supplied decisions connect
real code to:

- every Python source through `include`/`source_roots`, or a reasoned exclusion;
- one architecture role per analyzed module and the intended `allow` graph;
- test, migration, and script zones;
- DTO, snapshot, schema, exception, and enum roles or exact symbols;
- the single Response mapper name and explicit field mapping inside that mapper;
- transaction owner roles, session providers, or transaction decorators;
- pytest HTTP-fixture roles or exact fixture symbols;
- external modules, logged calls, and approved wrappers;
- approval and inline-ignore budgets, which default to zero.

The generated file is an initial observation, not proof that these details are correct.

### 5. Prove setup, then check code

```bash
uv run taut config validate .
uv run taut audit . --format json
uv run taut check . --no-cache --format json
```

Repeat `audit` until assurance is complete, then repeat `check` until policy violations are fixed.
Do not add approvals, inline ignores, broad allow edges, or false `absent` declarations merely to
make the commands green.

- Exit `0`: complete and compliant
- Exit `1`: definite enforced policy violations
- Exit `2`: configuration/assurance/analysis is incomplete or an enforced decision is unreliable

See the complete [new-project guide](docs/getting-started.md) for issue-by-issue remediation, an AI
handoff prompt, existing-project migration, and a CI example.

## Configuration reference

Define repository roles and allowed dependencies in `pyproject.toml`. Strict mode is enabled by
default and now includes assurance completeness. File length remains a repository policy parameter.

```toml
[tool.taut]
schema_version = 5
packs = ["taut.backend"]
providers = [
    "taut.python-core",
    "taut.fastapi",
    "taut.pydantic",
    "taut.pytest",
    "taut.sqlalchemy",
    "taut.tortoise",
]
strict = true
source_roots = ["."]
# Optional: re-include owned source under an engine-default ignored directory.
# force_include = ["build/owned_package/**/*.py"]

[tool.taut.roles.router]
include = ["app/router/*.py", "app/router/**/*.py"]

[tool.taut.roles.service]
include = ["app/service/*.py", "app/service/**/*.py"]

[tool.taut.allow]
router = ["router", "service"]
service = ["service"]

[tool.taut.zones]
test = ["tests/*.py", "tests/**/*.py"]

[tool.taut.transaction]
owner_roles = ["service"]
session_providers = ["app.database.get_async_session"]
# Decorator-managed projects may use:
# boundary_decorators = ["app.database.atomic"]
# Atomic context managers are distinct from plain session lifetime:
# boundary_contexts = ["app.database.atomic_session"]

[tool.taut.code_conventions]
response_mapper_name = "from_internal"

[tool.taut.assurance]
max_approvals = 0
max_inline_ignores = 0

[tool.taut.assurance.features]
api = "required"
schema = "required"
dto = "required"
snapshot = "absent"
exception_registry = "required"
enum = "required"
database = "required"
transaction = "required"
external_calls = "required"
security = "required"
tests = "required"
migrations = "absent"
scripts = "absent"
```

Every feature key is mandatory in strict mode. `required` needs real semantic evidence and active
roles, symbols, and zones. `absent` fails if matching evidence appears. Ambiguous exact paths or
symbols can be classified only with a reasoned `[[tool.taut.assurance.assertions]]` entry.

Required activation symbols are checked against the analyzed program. A stale symbol produces
`POLICY_SYMBOL_UNRESOLVED`; a local class/value/callable of the wrong kind produces
`POLICY_SYMBOL_KIND_MISMATCH`. Response contracts use exactly one configured mapper name. The
mapper must be a typed `classmethod`, and its body must map fields explicitly—renaming it to
`from_result` is supported, but bulk `model_dump()`/`model_validate()` or `**payload` copying is
still rejected. DTO immutability accepts frozen dataclasses and Pydantic models configured with
`ConfigDict(frozen=True)`, including inheritance from a proven frozen base.

`TEST002` trusts only pytest fixtures whose decorator and dependency chain are present in the
`taut.pytest.fixtures@1` capability. Approve the fixture by a configured fixture role or an exact
`test_http_fixture_symbols` entry; a same-named ordinary parameter is not sufficient.

Every Python file below the project root must be analyzed or excluded with a reason:

```toml
[[tool.taut.exclusions]]
patterns = ["generated/*.py"]
reason = "generated from the versioned API schema"
```

Taut always excludes common repository noise such as VCS metadata, virtual environments, tool
caches, build outputs, and `node_modules`. A reasoned exclusion above is also an actual discovery
exclusion, so project-specific paths do not need to be repeated in `tool.taut.exclude`. The legacy
`exclude` list remains supported as an additive list, but strict audit still requires a reason for
omitted Python sources.

Validate the effective configuration before the first full check:

```bash
uv run taut config validate .
uv run taut check .
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

An external wrapper may be the configured callable that directly owns the external call (for
example a centralized HTTP client `_request` method) or a configured context manager enclosing it.
Calls outside those exact boundaries still fail `LOG001`.

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
taut config schema --format json
taut init . --format json
taut audit . --format json
taut check .
taut check . --verbose
taut check . --format json
taut check . --daemon auto
taut rules --format json
taut rules ASYNC001 --format json
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
taut check /path/to/project --config /path/to/audit-policy.toml --no-cache
```

Role patterns and `source_roots` are resolved relative to the target project, not the
configuration file. The `.policy/policy.toml` location and explicit external configuration files
remain supported. Configuration content uses schema v5. Checks reject v1-v4 with an exact
`taut config migrate` command. Migration prints v5 without changing the source unless an explicit
output path is supplied; generated feature decisions start at `absent`, so the first audit exposes
every detected policy surface that must be reviewed.

## Results

The default terminal output prints one finding per line followed by the error and warning totals.
Long findings wrap to the next indented line. Non-terminal output uses a width of 120 characters;
override it with an option such as `--width 100`. Use `--verbose` only when you need related
locations, remediation guidance, decision counts, and the decision digest.

JSON report schema v5 includes a structured assurance report in addition to resolved, unresolved,
ambiguous, and dynamic call/reference counts;
resolved and unresolved imports; unavailable capabilities; skipped evaluations; and coverage gaps.
It reports used and unused symbol approvals separately from inline ignores. A rule runs only when
its declared semantic capabilities are present.

- Exit code `0`: no enforced violations
- Exit code `1`: one or more enforced violations
- Exit code `2`: invalid/incomplete assurance, analysis failure, or an enforced rule that could not
  be evaluated

When an exception is unavoidable, suppress only the exact rule on the affected line:

```python
legacy_call()  # taut: ignore[ASYNC001]
```

An ignore without a rule ID, or with an unknown rule ID, is a configuration error. An ignore that
does not suppress a real violation is reported as `IGNORE001`. File-wide ignores, violation
baselines, and expiration management are intentionally unsupported.

Raw SQL is not generally allowed. Application code should use SQLAlchemy or Tortoise ORM
expressions. A necessary raw query must pass through a registered shared wrapper configured with
`raw_query_roles` and `raw_query_wrappers`. Fixed Model `server_default` expressions and partial
Index predicates are allowed only within `schema_sql_roles` and `schema_sql_argument_names`.

Registered raw-query calls must provide `name`, `statement`, and `parameters` as explicit keyword
arguments. `name` and `statement` must be string literals, preventing SQL construction through
f-strings or string concatenation.

## Built-in rules

With the default `strict = true`, `CAT001` is advisory and the other 48 rules are enforced.
Individual rules cannot be disabled. Use `strict = false` before adoption to report every finding
as a warning.

| Group | Rules |
|---|---|
| Architecture | `ARCH000`-`002`, `BOUNDARY001`-`003`, `ENTRY001`, `SERVICE001`, `QUERY001`, `MODEL001`, `ADAPTER001`-`002`, `WIRING001`, `CONFIG001`, `DEPENDS001` |
| Runtime safety | `TIME001`, `ASYNC001`, `RUNTIME001`, `IMPORT001`, `IMPORT002`, `SIZE001`, `SEC001` |
| Database and transactions | `TX001`-`003`, `SESSION001`-`003`, `ORM001`, `ORM002`, `DB001`, `SQL001` |
| External calls | `HTTP001`, `LOG001`, `CAT001` |
| Data contracts | `DTO001`, `DTO002`, `SNAPSHOT001`, `SCHEMA001`-`003`, `API001`-`003`, `ENUM001`, `EXC001` |
| Test boundaries | `TEST001`, `TEST002` |
| Inline ignores | `IGNORE001` |

Each rule declares whether it applies to `prod`, `test`, `migration`, or `script` code. Missing
roles, dependency cycles, import placement, file size, dynamic execution, async safety, and
security access are checked in every zone. API, DTO, database, and service-boundary rules apply to
production code.

Resolution-state applicability follows the resolver facts, not source spelling. Conditional
execution is represented by `SyntaxContext.guard` and does not weaken an otherwise resolved symbol;
`ResolutionState.CONDITIONAL` means the binding or identity itself is available only on some paths.
Conditional and ambiguous identities carry resolver candidates and can yield `indeterminate` when a
configured symbol is a candidate; unresolved and dynamic references do not identify a configured
target, so each group-C rule follows its matrix row (`evaluate`-compatible for rules that can
continue, `not_applicable` where no target exists). This preserves unrelated-uncertainty behavior
and avoids manufacturing relevance from written names.

The built-in backend pack contains all 49 rules. It consumes versioned semantic capabilities from
the built-in Python provider (`taut.syntax@1`, `taut.bindings@1`, `taut.imports@1`, and
`taut.uses@1`). Third-party integrations can use the public `taut.plugins.v1` and
`taut.semantic.v1` contracts without importing the concrete AST analyzer. See
[`docs/plugins.md`](docs/plugins.md) for a complete rule-pack entry-point example.

Fact providers are loaded through the `taut.fact_providers.v1` entry-point group. A provider
declares a stable `id`, numeric dotted `version`, `provides` capability specifications such as
`example.types@1`, and optional `requires` entries (`ProviderDependency`). Providers are composed
deterministically by dependency then `(id, version)` order. Each capability must have exactly one
owner; a provider that fails or returns a payload different from its declaration is isolated and
reported as unavailable with an actionable reason. Successful capabilities retain provider/version
provenance in the snapshot and JSON analysis coverage, so integrations can reproduce a decision.

When `taut.backend` is used without an explicit `providers` setting, configuration loads the
built-in providers in stable order: `taut.python-core`, `taut.fastapi`, `taut.pydantic`,
`taut.pytest`, `taut.sqlalchemy`, and `taut.tortoise`. An explicit `providers` list is authoritative (for example,
listing only `taut.python-core` intentionally omits framework providers); provider IDs must be
unique.

### Tortoise ORM

The built-in `taut.tortoise` provider recognizes `Model` inheritance, `fields.*Field`
declarations, relationship fields, model/query-set reads and writes (including QuerySets returned
through first-party helpers), transaction contexts, and
raw SQL through `Model.raw`, `RawSQL`, or `BaseDBAsyncClient.execute_*`. These facts participate in
database assurance, layer boundaries, query write restrictions, transaction checks, and `SQL001`.

When application code uses Tortoise's context manager directly, configure it as both the session
provider and an atomic transaction context:

```toml
[tool.taut.transaction]
owner_roles = ["service"]
session_providers = ["tortoise.transactions.in_transaction"]
boundary_contexts = ["tortoise.transactions.in_transaction"]
```

For a project-owned wrapper, also declare the type yielded by that wrapper so calls on the
connection resolve semantically:

```toml
[tool.taut.transaction]
owner_roles = ["service"]
session_providers = ["app.db.transaction"]
boundary_contexts = ["app.db.transaction"]

[tool.taut.transaction.provider_item_types]
"app.db.transaction" = "tortoise.backends.base.client.TransactionalDBClient"
```

`session_providers` describes resource lifetime; it does not prove atomicity. Put only genuinely
atomic context managers in `boundary_contexts`. `provider_item_types` keys must also appear in
`session_providers`. SQLAlchemy wrappers remain
backward compatible and default to `sqlalchemy.ext.asyncio.AsyncSession` when no item type is
specified.

`ORM001`, `ORM002`, and `DB001` keep their SQLAlchemy-specific meanings. Tortoise does not expose
equivalent per-relationship lazy-loading or per-column timezone options, so Taut does not pretend
those SQLAlchemy checks apply. Tortoise's framework-specific model configuration should be added
as separate rules when there is a precise, enforceable contract.

An unregistered call that might have an external effect cannot be proven unsafe, so it is reported
as a `CAT001` warning. After classifying the call, add it to the project effect catalog for precise
enforcement.

## Development

```bash
bash scripts/test.sh
bash scripts/test.sh --only tests/unit/policy/test_builtin_rules.py -x
```

When validating unpublished local changes, avoid `uvx --from /path` for two different builds that
share the same package version: uv may reuse an earlier local wheel. Use a fresh environment and
force a source rebuild instead:

```bash
uv venv --python 3.13 /tmp/taut-validation
uv pip install --python /tmp/taut-validation/bin/python --refresh --reinstall /path/to/taut
/tmp/taut-validation/bin/taut check /path/to/project --no-cache
```

The full check runs the repository's own policy rules, Ruff, mypy strict, Pyright strict, pytest
with at least 90% branch coverage, package builds, and an isolated wheel installation.

See [`MIGRATION.md`](MIGRATION.md) for the 0.1.x upgrade checklist and [`docs/VALIDATION_REPORT.md`](docs/VALIDATION_REPORT.md)
for reproducible release checks. See [`docs/README.md`](docs/README.md) for current design documents.
