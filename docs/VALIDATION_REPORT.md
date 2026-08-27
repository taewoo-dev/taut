# pytaut 0.3.0 validation report

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
