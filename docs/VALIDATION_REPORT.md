# pytaut 0.2.0 validation report

Run `bash scripts/test.sh` from the repository root to reproduce release checks: conventions,
Ruff, mypy, Pyright, the self-policy check, the full pytest suite with branch coverage, and both
sdist/wheel builds. The script installs the wheel with `uv run --isolated --no-project` and checks
that the installed package imports as version `0.2.0`.

The compatibility contract is deterministic for configuration/effective-policy serialization,
provider ordering and provenance, decision digests, JSON key ordering, and text output for the
same input. Supported CLI commands include `taut config validate`, `taut config explain --format
json`, `taut check --format json`, `taut check --daemon auto`, `taut daemon start/status/stop`,
`taut cache stats/clean`, `taut rules`, and `taut config migrate`; migration is source-preserving
unless `--output` is supplied.

The final release-candidate gate passed 1,094 tests at 90.00% branch coverage and built
`pytaut-0.2.0.tar.gz` plus `pytaut-0.2.0-py3-none-any.whl`. The isolated wheel imported as
version `0.2.0`. Anti-monitor cache and daemon measurements are recorded in
[`performance/anti-monitor-0.2.0.json`](performance/anti-monitor-0.2.0.json).

See [`MIGRATION.md`](../MIGRATION.md) and the machine-readable
[`uncertainty-migration-matrix.json`](refactoring/backend-taut/uncertainty-migration-matrix.json).
