# taut

`taut` makes hidden Python backend conventions explicit and blocks only violations it can
determine reliably. The same source and configuration always produce the same result. It does
not hard-code the names or directory layout of any company or service.

The first PyPI release is being prepared. Until it is published, install directly from GitHub:

```bash
uv add --dev "taut @ git+https://github.com/taewoo-dev/taut.git"
uv run taut check .
```

After the PyPI release, installation becomes:

```bash
uv add --dev taut
```

## Configuration

Define repository roles and allowed dependencies in `pyproject.toml`. Strict mode is enabled by
default, and the built-in maximum file length is 700 lines.

```toml
[tool.taut]
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

## Commands

```bash
taut config validate .
taut check .
taut check . --verbose
taut check . --format json
taut rules
taut rules ASYNC001
```

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
configuration file. The legacy `.policy/policy.toml` format and explicit external configuration
files remain supported.

## Results

The default terminal output prints one finding per line followed by the error and warning totals.
Long findings wrap to the next indented line. Non-terminal output uses a width of 120 characters;
override it with an option such as `--width 100`. Use `--verbose` only when you need related
locations, remediation guidance, decision counts, and the decision digest.

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

See [`docs/README.md`](docs/README.md) for the current design documents.
