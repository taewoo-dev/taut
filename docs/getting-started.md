# Start using pytaut in a project

This guide covers the complete path from a repository without Taut to strict CI. It describes
pytaut 0.3.0 and configuration schema v4.

## Choose the correct entry path

Use `taut init` only when the repository has no `[tool.taut]` section and no
`.policy/policy.toml` file.

| Repository state | Start with |
|---|---|
| No Taut configuration | `taut init . --format json` |
| Existing schema-v4 configuration | `taut audit .` |
| Existing schema v1-v3 | `taut config migrate . --output migrated-policy.toml` |

`init` refuses an existing configuration during preview as well as during write. It never merges
or replaces an existing policy.

## 1. Install a fixed version

```bash
uv add --dev pytaut==0.3.0
uv run taut --version
```

Pinning the version makes local and CI decisions reproducible. Python 3.12 or newer is required.

## 2. Generate the read-only proposal

```bash
uv run taut init . --format json > taut-init.json || test "$?" -eq 2
```

The responsibilities are deliberately separate:

- Taut reads Python sources and prints JSON to standard output.
- The shell creates `taut-init.json` because of `>`.
- Exit code `2` means unresolved onboarding questions; it is expected for the first proposal.
- No Taut configuration is written without `--write`.

The proposal includes a status, Python paths, detected features, role/import observations,
recommended answers, proposed TOML, and a project digest. Treat recommendations as evidence to
review, not decisions to accept blindly.

### Digest scope

The digest contains each discovered Python file path and its bytes. These changes make answers
stale:

- adding or deleting a Python file;
- editing Python source;
- renaming or moving a Python file.

README, frontend, lockfile, and other non-Python changes do not currently affect the digest.

## 3. Create the answers file

The 0.3.0 answers contract supports only:

```json
{
  "project_digest": "value returned by init",
  "accept_observed_architecture": true,
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

All 13 feature keys are required. `required` says the capability belongs in the repository and
must have real code evidence plus active policy configuration. `absent` says matching evidence is
an error.

The answers contract does not support detailed role edits, exclusions, zones, or exact symbols.
An AI or developer performs those edits in TOML after the write.

## 4. Write once, safely

```bash
uv run taut init . --answers taut-init-answers.json --write
```

Taut refuses to write when questions are unresolved, the digest changed, the target configuration
already exists, or the project file is invalid. A successful write uses a temporary sibling file,
flushes it, and atomically replaces the target.

## 5. Review the generated TOML

Review every category below before treating the policy as complete.

### Source scope

Every Python file below the project root must be analyzed or excluded with a durable reason.

```toml
[tool.taut]
include = ["app/*.py", "app/**/*.py", "tests/*.py", "tests/**/*.py"]
source_roots = ["."]

[[tool.taut.exclusions]]
patterns = ["generated/*.py"]
reason = "generated from the committed API schema"
```

An ordinary `exclude` controls discovery but does not explain an assurance omission. Use a
reasoned exclusion when a Python file intentionally remains outside analysis.

### Roles and dependencies

Every analyzed module needs exactly one role, and every role needs an explicit dependency allow
list. Review observed edges; do not keep a broad edge only because the current code imports it.

```toml
[tool.taut.roles]
router = ["app/routers/*.py"]
service = ["app/services/*.py"]
model = ["app/models/*.py"]

[tool.taut.allow]
router = ["router", "service"]
service = ["service", "model"]
model = ["model"]
```

### Zones

Connect non-production code explicitly.

```toml
[tool.taut.zones]
test = ["tests/*.py", "tests/**/*.py"]
migration = ["migrations/*.py", "migrations/**/*.py"]
script = ["scripts/*.py", "scripts/**/*.py"]
```

### Exact policy activation

Required features often need repository-specific symbols:

```toml
[tool.taut.transaction]
owner_roles = ["service"]
session_providers = ["app.db.get_async_session"]

[tool.taut.code_conventions]
dto_roles = ["dto"]
snapshot_roles = ["snapshot"]
request_config_symbols = ["app.schemas.REQUEST_MODEL_CONFIG"]
response_config_symbols = ["app.schemas.RESPONSE_MODEL_CONFIG"]
exception_base_symbols = ["app.exceptions.DomainError"]
error_code_enum_symbols = ["app.enums.ErrorCode"]

[tool.taut.external]
logged_calls = ["httpx.AsyncClient.get", "httpx.AsyncClient.post"]
wrappers = ["app.observability.external_call"]

[tool.taut.enum]
shared_modules = ["app.enums"]
```

Use symbols that exist in the repository. Stale selectors and assertions are assurance failures.

### Exception budgets

Start with no policy exceptions:

```toml
[tool.taut.assurance]
max_approvals = 0
max_inline_ignores = 0
```

Increase a budget only after reviewing an exact, reasoned exception. Never use a budget increase
as a generic adoption baseline.

## 6. Run the assurance loop

```bash
uv run taut config validate .
uv run taut audit . --format json > taut-audit.json
```

Common assurance codes have direct actions:

| Code | Meaning | Correct action |
|---|---|---|
| `SOURCE_UNACCOUNTED` | Python source is neither analyzed nor reasonedly excluded | Expand source scope or add a narrow exclusion with a reason |
| `ROLE_UNCLASSIFIED` | An analyzed module has no role | Add the exact module pattern to one role |
| `ROLE_SELECTOR_UNUSED` | A configured role matches nothing | Fix or remove the stale selector |
| `ZONE_SELECTOR_UNUSED` | A configured zone matches nothing | Fix or remove the stale selector |
| `FEATURE_REQUIRED_MISSING` | A required capability has no code evidence | Correct the expectation or implement the capability |
| `FEATURE_ABSENT_DETECTED` | Code contradicts an absent declaration | Mark it required and configure it, or use an exact reasoned assertion when truly not applicable |
| `FEATURE_POLICY_INACTIVE` | Evidence exists but its role/symbol/zone policy is not active | Connect the corresponding policy settings |
| `EXCLUSION_UNUSED` / `ASSERTION_UNUSED` | An exception became stale | Remove or correct it |
| `APPROVAL_BUDGET_EXCEEDED` / `IGNORE_BUDGET_EXCEEDED` | Used exceptions exceed the declared budget | Remove exceptions or deliberately review the exact budget |

Repeat until `audit` exits `0`. Do not proceed to strict CI with assurance exit `2`.

## 7. Run the policy loop

```bash
uv run taut check . --no-cache --format json > taut-check.json
```

| Exit | Meaning | Next action |
|---|---|---|
| `0` | Complete and compliant | Add CI |
| `1` | Definite enforced violation | Fix code or architecture; use an exact approval only when justified |
| `2` | Trust failure | Fix configuration, assurance, analysis, coverage, or indeterminate evaluation |

Use `--no-cache` for the canonical release/CI decision. Cache and daemon modes are useful for local
feedback but do not change findings.

## 8. Add CI only after both commands are green

```yaml
- name: Validate Taut configuration
  run: uv run taut config validate .

- name: Audit Taut assurance
  run: uv run taut audit . --format json

- name: Check Taut policy
  run: uv run taut check . --no-cache --format json
```

Keep the same pytaut version in the lockfile locally and in CI.

## Existing projects

Do not run `init` over an existing policy. For schema v1-v3:

```bash
uv run taut config migrate . --output migrated-policy.toml
uv run taut config validate . --config migrated-policy.toml
uv run taut audit . --config migrated-policy.toml --format json
uv run taut check . --config migrated-policy.toml --no-cache --format json
```

Migration intentionally starts feature decisions at `absent`. Review detected features, change
real capabilities to `required`, activate their settings, and account for excluded Python files
before replacing the old configuration.

## Prompt for an AI coding agent

```text
Install the repository-pinned pytaut version and onboard this Python project safely.

1. If no Taut configuration exists, run `taut init . --format json`. Treat exit 2 as expected
   while questions remain. Do not claim that the proposal is a finished policy.
2. Review evidence and create answers containing only project_digest,
   accept_observed_architecture, and all 13 required/absent feature decisions.
3. Run init with --answers and --write. Never overwrite an existing Taut configuration.
4. Review and correct source scope, reasoned exclusions, roles, allow edges, zones, exact symbols,
   transaction providers, external-call wrappers, and exception budgets in pyproject.toml.
5. Repeat `taut audit . --format json` until exit 0, then repeat
   `taut check . --no-cache --format json` until exit 0.
6. Do not weaken strict mode, declare real features absent, add broad allow edges, create blanket
   approvals, or add inline ignores merely to pass.
7. Report every configuration change, remaining exception, command, exit code, diagnostic,
   assurance issue, engine issue, skipped evaluation, and coverage gap.
```
