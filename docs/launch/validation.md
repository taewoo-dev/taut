# Launch-kit validation

Validated locally on 2026-09-08. No remote workflow run or external adoption is
claimed by this report.

## Released-tool demonstration

`uv run --no-project --python 3.12 --locked examples/architecture/verify.py`
passed using Python **3.12.12** and the versions recorded in
[results.json](../../examples/architecture/results.json).

All 16 commands returned their expected exit codes. Both FastAPI endpoints
returned the expected HTTP 200 response; Ruff, strict mypy, and strict Pyright
passed in both variants. Taut config validation and assurance passed in both.
The only enforced diagnostic was `ARCH001` in `before`; `after` passed. Both
analysis reports had complete assurance and no reported gaps or indeterminate
checks. The application diff is one import; the shared policy was unchanged.

This is a hand-authored test case, not an AI-agent performance study or an
estimate of whole-project detection quality.

## Repository gate

`bash scripts/test.sh` passed on Python **3.14.0**:

- 1,405 tests passed; 25 optional native-wheel tests skipped.
- Total coverage with branch measurement: **90.49%**.
- Repository conventions, Ruff format/lint, strict mypy/Pyright, and self-policy passed.
- Wheel and source archive built; isolated installed-wheel import, config, and check smoke passed.

The original documentation-contract test expected the full onboarding contract
inside README. It now checks the preserved `docs/reference.md` and getting-started
guide, plus README links to both documents and the agent prompt. No engine rule
or CLI behavior was changed to make the demo pass.

The new independent demo workflow targets Linux/Python 3.12 and tests the published
release. Its remote result remains pending until these changes are pushed.

## Presentation checks

- Local Markdown file links checked for missing targets.
- Both helper scripts passed explicit Ruff lint and formatting checks.
- Six video scenes inspected using the contact sheet; the GIF and MP4 are 36-second
  paced replays, with provenance visible on every frame.
- Source and shared-policy hashes bind the media generator to the verified example.
- X launch copy: 265 plain Unicode characters, with a single project URL.
- Candidate research is dated, source-linked, and separate from adoption claims.

Reproduce or update the media using the commands in the [launch-kit index](README.md).
