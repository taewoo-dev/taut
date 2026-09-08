# A working endpoint with a broken architecture rule

This small FastAPI application returns a greeting from an in-memory repository.
Its policy says routers must access the repository through the service layer.
The `before` version breaks that rule; `after` fixes one import.

This is a **hand-authored example**, not evidence that a particular AI model
generated or repaired this code. The terminal results are real.

## Run the two checks

From the Taut repository root, with [uv](https://docs.astral.sh/uv/getting-started/installation/):

```bash
uvx --python 3.12 --from pytaut==0.10.0 taut check examples/architecture/before --no-cache
```

Expected exit **1**, with exactly one enforced diagnostic:

```text
app/router.py:3:1: error: [ARCH001] Role router imports app.repository from disallowed role repository.
Check complete: 1 error, 0 warnings
```

Then run:

```bash
uvx --python 3.12 --from pytaut==0.10.0 taut check examples/architecture/after --no-cache
```

Expected exit **0**:

```text
Check complete: no policy violations within supported scope
```

These commands install the published tool into uv's cache. They do not install
Taut from this checkout or modify either example's Python files.

## What changes

Both projects inherit [policy.toml](policy.toml) without overriding its settings.
The only application-code difference is in `app/router.py`:

```diff
-from app.repository import read_greeting as get_greeting
+from app.service import get_greeting
```

The service already calls the repository. The fix restores the intended route
through that service. No policy is weakened, ignored, or made advisory.

The example has an actual FastAPI router, but intentionally no database, DTOs,
Pydantic schema classes, authentication, or external API calls. Its `absent`
feature declarations describe those omissions; they are not a recipe for
onboarding a production application. For that, use [the setup guide](../../docs/getting-started.md).

## Verify the comparison

```bash
uv run --no-project --python 3.12 --locked examples/architecture/verify.py
```

The verification script has its own dependency lock, independent of Taut's
development environment. First use needs network access. Pyright requires Node.js
or its Python wrapper's ability to provision Node.js.

It checks both variants with:

| Check | Version / configuration | Before | After |
|---|---|---|---|
| Ruff | 0.12.12; isolated `E,F,I,UP,B`, Python 3.12 | Pass | Pass |
| mypy | 1.18.2; strict, explicit package bases, no incremental cache | Pass | Pass |
| Pyright | 1.1.405; strict, Python 3.12 | Pass | Pass |
| HTTP request | FastAPI 0.116.1, httpx 0.28.1; `GET /greetings/` | Same 200 response | Same 200 response |
| Taut config + assurance | pytaut 0.10.0 | Pass | Pass |
| Taut check | Same shared strict policy, no cache | `ARCH001`, exit 1 | Exit 0 |

This comparison concerns one project-specific dependency rule. It is not a
general accuracy or performance benchmark, and it does not imply the other
tools cannot be extended or configured with additional architecture checks.

The verifier also confirms that only the import changes, both configurations
inherit the same policy, assurance is complete, and there are no reported
analysis gaps or indeterminate checks. Unexpected results fail the script.

To regenerate the [recorded results](results.json):

```bash
uv run --no-project --python 3.12 --locked examples/architecture/verify.py --report examples/architecture/results.json
```

The report includes tool versions, commands, exit codes, source hashes, and the
shared policy hash. The [GIF and MP4](../../docs/launch/README.md) replay these
results with reading time; their duration is not the command execution time.

## Try an agent-assisted repair

Give your coding agent this instruction while keeping the original example intact:

> Copy `examples/architecture` to a temporary directory. In that copy, fix the
> architecture violation in `before/app/router.py`. Keep all policy files and
> configuration settings unchanged. Run pytaut 0.10.0 `audit` and `check --no-cache`
> on `before`, then show the code diff, diagnostics, and exit codes. Do not use the
> `after` directory as your check target. Do not claim success without running the checks.

This is an experiment users can run, not a guaranteed autonomous repair feature.
