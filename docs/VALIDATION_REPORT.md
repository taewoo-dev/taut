# pytaut validation report

## Unreleased follow-up — 2026-09-05

The follow-up based on `0dea529` passed `bash scripts/test.sh` on Python 3.14.0:
conventions, Ruff, strict mypy/Pyright, strict self-policy, 1,350 tests, 90.41% total
coverage with branch measurement, sdist/wheel builds, and an isolated installed-wheel smoke test.
Lambda invocation and valid direct callback effects now detect the two remaining selected
synthetic violations: six definite findings on six violations, no findings or uncertainty on
four safe controls. This is bounded regression evidence, not general accuracy.

The temporary 1,224-source anti-monitor snapshot passed its existing policy. Injected dangerous
lambda/callback cases failed as expected and matched fresh analysis; safe offloading and removal
restored success. Timing and memory observations, including the initially unstable memory sample
and stable recheck, are retained in the [real-project report](quality/antimonitor-followup.md).
Package version remains 0.9.0 and has not been published.

## Unreleased review improvements — 2026-09-05

The working tree based on `bfddf85` passed `bash scripts/test.sh` on Python 3.14.0:
repository conventions, Ruff formatting/lint, mypy strict, Pyright strict, strict self-policy,
1,331 tests, 90.36% total coverage with branch measurement, sdist/wheel builds, and an isolated
installed-wheel smoke check. Package version remains 0.9.0; these changes have not been published.
Other interpreter versions were not rerun locally for this review.

The same labeled synthetic async corpus was executed against the baseline source extracted with
`git archive` and the changed source. Of six dangerous snippets, definite detection increased
from two to four; one additional case is now indeterminate and one lambda case remains a silent
miss. Four safe controls produced neither findings nor indeterminate decisions in either version.
This does not estimate real-project accuracy. See [detection quality](detection-quality.md) for
raw results, metric definitions, limitations, adoption guidance, and the external pilot protocol.

Regression checks cover direct filesystem and Requests session operations, callback positional/
keyword/default binding, safe callable storage and offloading, shadowed names, preserving definite
findings in the presence of uncertainty, helper-edit resident/cold parity, selective advisory
adoption, promotion back to enforcement, and retention of strict assurance while staging a rule.

## 0.8.0 release candidate — 2026-09-05

`bash scripts/test.sh` passed on Python 3.14 with repository conventions, Ruff, mypy strict,
Pyright strict, the repository's own strict Taut policy, 1,284 tests, 90.36% branch coverage,
sdist/wheel builds, and an isolated installed-wheel smoke test.

The resident benchmark used anti-monitor commit `72279e5e5556ed4bc8c80d567878953b4dc40ae9`
with 1,213 Python sources. Against the Phase 4 baseline, median cold, ordinary-edit, shared-edit,
and restart wall times improved from 11.616, 2.349, 3.604, and 11.926 seconds to 10.991, 1.706,
3.302, and 11.414 seconds. Every timed stdout, stderr, and exit-code digest matched the fresh
oracle. Thirty consecutive unchanged resident checks held RSS at 858.6 MiB after the first sample.
The detailed methodology, rejected experiments, profiles, and native-acceleration decision are in
[`performance-roadmap.md`](performance-roadmap.md).

## 0.5.0 release candidate — 2026-09-02

`bash scripts/test.sh` passed on Python 3.14 with repository conventions, Ruff, mypy strict,
Pyright strict, the repository's own strict Taut policy, 1,203 tests, 90.20% branch coverage,
sdist/wheel builds, and an isolated installed-wheel smoke test. The built artifacts reported
`pytaut 0.5.0`; config validation and the installed policy check both exited 0.

The current source was also force-reinstalled into a fresh Python 3.13.9 environment and exercised
read-only against NEXUS and both Thready Python components:

- NEXUS used a temporary v4-to-v5 migrated external configuration, the observed project convention
  `response_mapper_name = "from_result"`, and the new pytest provider. It analyzed 950/950 sources
  with no failed/partial source, unavailable capability, engine issue, indeterminate evaluation,
  skipped evaluation, or coverage gap. It is not compliant: 2 assurance issues and 2,039 active
  diagnostics remain. Those are repository policy/configuration results, not analyzer trust
  failures. In particular, the previously unresolved forwarded endpoint-doc helper chain is now
  resolved statically.
- Thready backend and AI `init --format json` remained read-only and exited 2 as designed while
  questions were unanswered. They discovered 557 and 306 Python files respectively, both observed
  the single `from_internal` mapper convention, and both proposed the reviewed 700-line fallback
  with stricter role budgets rather than silently raising the fallback to fit outliers.

NEXUS retained its pre-existing modified `pyproject.toml` and `uv.lock`; Thready remained clean.
All validation configurations and reports were stored outside those repositories.

## 0.3.0 release

Run `bash scripts/test.sh` from the repository root to reproduce release checks: conventions,
Ruff, mypy, Pyright, the self-policy check, the full pytest suite with branch coverage, sdist/wheel
builds, and an isolated installation smoke test.

The final local release gate passed 1,141 tests at 90.15% branch coverage on Python 3.14. It built
`pytaut-0.3.0.tar.gz` and `pytaut-0.3.0-py3-none-any.whl`; the isolated wheel imported as version
0.3.0, validated the installed fixture, and completed its policy check. Release CI repeats the full
gate on Python 3.12, 3.13, and 3.14 before trusted publishing to PyPI.

The repository's own schema-v4 policy discovered 285 Python files at the final review point. Every
file was analyzed or covered by a reasoned exclusion, and the canonical no-cache check returned
exit code 0 with no diagnostics, assurance issues, engine issues, skipped rules, or coverage gaps.

The release candidate was also exercised read-only against all three backends in
`medisolveai-auth`. Their schema-v3 policies were migrated to temporary external v4 files; detected
features were explicitly marked required, package-marker exclusions received reasons, and the
migration zone was activated. All three then returned exit 0 from `taut audit` and the canonical
no-cache `taut check`, with no diagnostics, assurance issues, engine issues, skipped rules, or
coverage gaps. The validation target remained unchanged.

See [`MIGRATION.md`](../MIGRATION.md) for schema-v4 adoption and [`plugins.md`](plugins.md) for the
strict extension contract.
