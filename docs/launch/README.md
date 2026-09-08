# Taut launch kit

Prepared on 2026-09-08 for **pytaut 0.10.0**. These are local launch materials;
their presence does not mean a post has been published or a project has adopted Taut.

## Ready to review

- [Public introduction](../../README.md) and [runnable FastAPI demo](../../examples/architecture/README.md)
- [18-second GIF](assets/architecture-demo.gif) for the README
- [18-second MP4](assets/architecture-demo.mp4) for social posts
- [Poster](assets/poster.png) and [all-frame QA sheet](assets/contact-sheet.png)
- [Show GN, Show HN, X, and first-user recruitment copy](posts.md)
- [10 researched repositories and 3 pilot proposals](candidates.md)
- [30-day rollout and measurement log](rollout.md)
- [Exact comparison results](../../examples/architecture/results.json)
- [Validation results and remaining external steps](validation.md)

## Message and public claims

README headline:

> Your AI writes code. Taut checks your architecture.

GitHub About description:

> Check Python code against your project's architecture rules. Catch violations locally and enforce the same rules in CI.

Keep launch copy concrete and conversational: show a forbidden import, the
diagnostic, and the fix. Lead with the demo and agent setup; link to detailed
verification notes rather than repeating them in the opening paragraph.

Suggested GitHub topics: `python`, `static-analysis`, `architecture`, `linter`,
`ai-coding`, `developer-tools`, `policy-as-code`, `fastapi`.
The homepage can stay empty until there is a dedicated documentation site.

Supported claims: explicit project policies, deterministic static checks,
file/rule diagnostics, machine-readable output, and nonzero exits for CI.
The checked-in demo verifies one architecture rule against one small application.

Do not describe this release as automatically compiling arbitrary Markdown
rules, installing agent hooks, forcing every agent to run Taut, proving runtime
safety, or autonomously fixing code. Merge blocking requires a required CI job.
Do not label research candidates as users or reproduce their logos as endorsements.

## Regenerate the evidence and media

From the repository root:

```bash
uv run --no-project --python 3.12 --locked examples/architecture/verify.py --report examples/architecture/results.json
uv run --no-project --python 3.12 --locked docs/launch/render_demo.py
```

The renderer refuses failed or stale evidence. It builds the GIF and MP4 from
recorded CLI output and hashed example files. Six scenes each last three seconds;
this is reading time, not a performance measurement. All scenes disclose that
the example is hand-authored and the output is a paced replay.

Rendering needs macOS Menlo or Linux DejaVu Sans Mono / Liberation Mono. Pillow
and the bundled FFmpeg executable are isolated script dependencies, not Taut
runtime dependencies. Verify all six scenes using the contact sheet after editing.

An actual agent session is a follow-up artifact: capture the prompt, tool version,
full session, resulting diff, unchanged policy hash, and check results before
claiming a model repaired the example. See the demo's [agent experiment](../../examples/architecture/README.md#try-an-agent-assisted-repair).

## Before posting

Merge and push the reviewed files, confirm the new demo CI job passes on GitHub,
and open the public README links while signed out. The new assets are not in the
already-published v0.10.0 source tag; launch links intentionally target the updated
default branch while demo commands install the pinned PyPI release.

Use a real existing author account for each channel. Keep time available for
questions. Post the project once per launch channel and follow that channel's
current rules. [Show HN](https://news.ycombinator.com/showhn.html) and
[Show GN](https://news.hada.io/guidelines) both expect an immediately usable project;
submit the GitHub repository, not a promotional landing page.

## Research basis

[Ruff's first 200 releases](https://notes.crmarsh.com/ruff-the-first-200-releases)
describe initial HN/Twitter interest, subsequent project adoption, and sustained
maintainer engagement. [Context7's launch](https://upstash.com/blog/context7-llmtxt-cursor)
leads with broken AI-generated code and a visible improvement, followed by a
[shorter MCP usage path](https://upstash.com/blog/context7-mcp). This kit applies
those presentation patterns; they do not establish a predictable star-growth rate.
