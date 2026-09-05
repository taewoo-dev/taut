# pytaut validation report

## Unreleased memory follow-up at 29c6edc — 2026-09-05

`bash scripts/test.sh` passed on Python 3.14.0: 1,383 tests, 90.55% total coverage with branch
measurement, repository conventions, Ruff, strict mypy/Pyright, strict self-policy, wheel/sdist
builds, and installed-wheel smoke checks. Module-local symbol sharing and per-build function
summary sharing preserve distinct source revisions and direct/approved-wrapper access paths.
The extractor is released without waiting for cyclic GC on both success and injected failure.
The existing three seeds of 100 synthetic edits continue to match fresh JSON and release
obsolete snapshots.

The session-object census shows 16,156 → 74 function summaries and 184,857 → 115,258 symbol
IDs without changing their distinct values. Shallow-size sums decrease 343.18 → 308.63 MiB from
the preceding implementation; this is not an RSS measurement. The separate [memory follow-up](quality/memory-followup.md)
records the warmed RSS protocol, raw results, and remaining limits while preserving the earlier
failed memory acceptance report. No package was published.

Under the explicit 50-edit warmup protocol, both 200 unchanged and 100 mixed-edit RSS series
pass the full plateau criterion. Median RSS is 756.45 → 773.20 MiB unchanged and
851.05 → 773.63 MiB mixed. The 10% reduction target remains unmet: unchanged RSS increases
2.21%, while mixed RSS decreases 9.10%. These are shared-machine observations.

## Unreleased performance implementation at 9aac0ad — 2026-09-05

The final `bash scripts/test.sh` gate passed on Python 3.14.0: 1,380 tests, 90.55% total
coverage with branch measurement, repository conventions, Ruff, strict mypy/Pyright,
strict self-policy, wheel/sdist builds, and installed-wheel smoke checks.

On the isolated 1,224-source anti-monitor snapshot, 20 samples per edit scenario show median
ordinary latency 1.86 → 1.33 seconds and shared latency 4.57 → 2.49 seconds. Five fresh daemon
starts show 11.63 → 11.39 seconds. The edit-median targets and cold/p95 regression limits pass.
Two hundred unchanged checks, 100 semantic edits, 30 additional per-edit fresh JSON comparisons,
and three seeds of 100 synthetic edits preserve the applicable fresh outputs.

**Memory acceptance remains unmet:** RSS medians decrease 6.65%/2.25% in unchanged/mixed runs,
below the 10% target; both baseline and candidate fail the full-series plateau criterion.
This shared-machine observation is not proof of a leak. All raw data and limitations remain
in the [acceptance report](quality/performance-implementation.md). No package was published.

## Performance investigation at 77dce3e — 2026-09-05

The unchanged engine passed the full gate again: 1,363 tests and 90.42% coverage with branch
measurement. The anti-monitor daemon benchmark passed fresh-output parity, restart/concurrent
checks, and 30-check memory stability. Separate ordinary/shared edit profiles also matched
fresh JSON results. Project assembly and broad shared-edit policy/provider recomputation are
the next measured optimization candidates. See [the test report](quality/performance-investigation.md)
for timings, profiles, memory, and limits; engine code was not changed in this test pass.

## Unreleased callback forwarding — 2026-09-05

The follow-up based on `5698c7b` passed `bash scripts/test.sh` on Python 3.14.0:
1,363 tests, 90.42% total coverage with branch measurement, conventions, Ruff, strict
mypy/Pyright, strict self-policy, package builds, and installed-wheel smoke checks.
New regression cases cover positional/keyword multi-hop forwarding, reverse definition order,
cycles with and without guarded invocation, safe storage/offloading/reassignment, and transitive
cross-module edits with resident/fresh parity. No package was published.

The same temporary anti-monitor snapshot passed, and an injected multi-hop blocking callback
produced ASYNC001 with resident/fresh parity. Current stage timings and the scope of the Rust
decision are recorded in [the native revisit](quality/native-revisit.md).

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
