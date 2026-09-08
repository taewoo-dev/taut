# 30-day launch runbook

Day 1 is the day the release kit becomes publicly reachable, not the date these
drafts were written. Default: one maintainer, no paid ads, no assumed existing
audience. Goals are operating targets, not a forecast: **100 stars, 10 external
trial users, 3 external repositories still using Taut after seven days**.

## Sequence

| Window | Action | Evidence before moving on |
|---|---|---|
| Days 1–7 | Publish the reviewed kit, set GitHub About/topics, recruit five trial users using the prepared copy | Public demo and CI work; record each observed obstacle |
| Days 8–10 | Publish the Show GN post; answer installation and scope questions | Correct misleading copy or broken first-use steps |
| Days 11–14 | Publish Show HN and the X video; set aside time for author responses | Store post URLs and take a GitHub traffic snapshot |
| Days 15–21 | Offer the three researched pilot proposals to relevant maintainers; begin with the smallest accepted boundary | Maintainer-defined rule, pinned source, reproducible before/after results |
| Days 22–30 | Write one evidence-backed adoption or first-use case on the author's own channel | Link approved public evidence; follow up on seven-day continued use |

If a pilot is declined, continue with consenting trial users rather than filing
unsolicited tool-install PRs. If no external adoption exists, publish what people
found confusing and what was improved; do not fill the slot with a fabricated case.

## Measurement

Take a snapshot at launch and twice a week. GitHub traffic only retains a short
history, so record snapshots while available. Use GitHub stars/traffic and
voluntary issue reports; the package gains no telemetry.

- **Trial user:** a unique external person confirms they ran the example or
  onboarding. Package downloads, CI runs, and stars are not unique users.
- **Adopted repository:** a maintainer confirms Taut is part of the workflow;
  mark sustained adoption only after a seven-day follow-up.
- **Public case:** source/config and results are public or approved for sharing.
  A candidate list entry is not adoption.

Interpret the data before the next post: few views suggests a message/channel
problem; views and stars without trials suggests a difficult entry path; trials
without continued use suggests onboarding cost, false positives, or unclear value.

## Baseline and status

Read-only GitHub/PyPI check on **2026-09-08**:

| Metric | Baseline | Source |
|---|---|---|
| Public repository | taewoo-dev/taut | [GitHub](https://github.com/taewoo-dev/taut) |
| Stars / forks / open issues | 0 / 0 / 0 | [Repository API](https://api.github.com/repos/taewoo-dev/taut) |
| Published version | 0.10.0, 2026-09-07 | [PyPI](https://pypi.org/project/pytaut/0.10.0/) |
| External trials / adopters | Not yet measured | No participants contacted during kit preparation |
| Published launch posts | None from this workflow | Drafts only |

Published in [PR #14](https://github.com/taewoo-dev/taut/pull/14): README, demo,
verification, media, logos, issue form, CI job, post drafts, and candidate research.
The independent release demo passed remotely. Full CI scope corrections and
main-branch publication are being finalized; consult the PR for live status.
Launch posts, trial recruitment, pilot contacts, adoptions, and follow-ups remain
unperformed. Prepared drafts are not published launch posts or adoption evidence.

## Append observations

| Date | Channel/post URL | Views / unique visitors / clones | Stars | Confirmed trials | Confirmed adopters / seven-day retention | Main obstacle / next action |
|---|---|---|---|---|---|---|
| 2026-09-08 | Preparation only | Not measured | 0 | Not measured | Not measured | Complete public rollout after review |

Keep private participant details outside this public repository. Store only
consented public handles, issue URLs, aggregated counts, and published evidence.
