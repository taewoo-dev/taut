# pytaut 0.2.0 validation report

Run `bash scripts/test.sh` from the repository root to reproduce release checks: conventions,
Ruff, mypy, Pyright, the self-policy check, the full pytest suite with branch coverage, and both
sdist/wheel builds. The script installs the wheel with `uv run --isolated --no-project`, checks
that the installed package imports as version `0.2.0`, validates an independent fixture project,
and runs its policy check through the installed `taut` executable.

The compatibility contract is deterministic for configuration/effective-policy serialization,
provider ordering and provenance, decision digests, JSON key ordering, and text output for the
same input. Supported CLI commands include `taut config validate`, `taut config explain --format
json`, `taut check --format json`, `taut check --daemon auto`, `taut daemon start/status/stop`,
`taut cache stats/clean`, `taut rules`, and `taut config migrate`; migration is source-preserving
unless `--output` is supplied.

The final release-candidate gate passed 1,131 tests at 90.18% branch coverage on Python 3.14 and
built `pytaut-0.2.0.tar.gz` plus `pytaut-0.2.0-py3-none-any.whl`. The isolated wheel imported as
version `0.2.0`; its configuration validation and end-to-end check also passed. CI and release
verification cover Python 3.12, 3.13, and 3.14.

A fresh Python 3.13.9 source installation checked the anti-monitor backend with no cache or daemon.
It returned exit code 1 for 17 active violations (`SESSION003` 8, `SEC001` 4, `LOG001` 2,
`SQL001` 2, and `ORM002` 1), with zero indeterminate evaluations and zero engine issues. Seven
approved diagnostics remained inactive (`IMPORT001` 6 and `WIRING001` 1). Cache and daemon
measurements are recorded in
[`performance/anti-monitor-0.2.0.json`](performance/anti-monitor-0.2.0.json).

See [`MIGRATION.md`](../MIGRATION.md) and the machine-readable
[`uncertainty-migration-matrix.json`](refactoring/backend-taut/uncertainty-migration-matrix.json).
