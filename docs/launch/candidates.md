# External repository research and pilot proposals

Checked on **2026-09-08** using public GitHub metadata and, for the three selected
projects, their own architecture documentation, source tree, and Python manifest.
These are research candidates, **not users, partners, audited projects, or known
violations**. No messages, issues, or pull requests were sent.

Stars below are a dated cumulative popularity signal, not evidence of a recent
trending spike. All ten repositories were unarchived when checked. The
[metadata snapshot](candidate-snapshot.json) records the source endpoints.

## Initial pool

| Repository | Stars | Last push (UTC date) | Fit and next step |
|---|---:|---|---|
| [fastapi/full-stack-fastapi-template](https://github.com/fastapi/full-stack-fastapi-template) | 45,447 | 2026-09-03 | Broad template reach. First check its actual conventions; do not impose our service-layer example on it. |
| [benavlabs/FastAPI-boilerplate](https://github.com/benavlabs/FastAPI-boilerplate) | 2,072 | 2026-08-08 | **Pilot 1:** explicit vertical-slice architecture and smaller template audience. |
| [fastapi-practices/fastapi-best-architecture](https://github.com/fastapi-practices/fastapi-best-architecture) | 2,539 | 2026-09-07 | **Pilot 2:** documented API/service/CRUD layers directly explain the value. |
| [langflow-ai/langflow](https://github.com/langflow-ai/langflow) | 154,442 | 2026-09-08 | AI application with large reach. Defer until a smaller pilot establishes onboarding cost. |
| [BerriAI/litellm](https://github.com/BerriAI/litellm) | 58,272 | 2026-09-08 | AI gateway; mixed Rust/Python scope and unusual default branch need investigation. |
| [open-webui/open-webui](https://github.com/open-webui/open-webui) | 151,304 | 2026-09-08 | AI application; backend scope must be separated from frontend before a pilot. |
| [agno-agi/agno](https://github.com/agno-agi/agno) | 42,099 | 2026-09-08 | Agent platform. First identify an application-policy use case rather than assume backend rules fit every SDK module. |
| [assafelovic/gpt-researcher](https://github.com/assafelovic/gpt-researcher) | 29,353 | 2026-08-27 | **Pilot 3:** AI project with an explicit agent-facing architecture reference. |
| [unclecode/crawl4ai](https://github.com/unclecode/crawl4ai) | 81,950 | 2026-09-08 | AI-related crawler; browser/runtime effects need separate semantic-scope investigation. |
| [langchain-ai/langgraph](https://github.com/langchain-ai/langgraph) | 41,251 | 2026-09-06 | Agent library; package isolation and library conventions require further review. |

The seven unselected projects received metadata-level screening only. Their
Python compatibility and full architecture policies have not been validated.

## Pilot 1: Fastro / Benav Labs FastAPI Boilerplate

Source snapshot: `2b6373d922bc993c7706c25a53f8dbab4e00217f`.

Its [project-structure guide](https://github.com/benavlabs/FastAPI-boilerplate/blob/2b6373d922bc993c7706c25a53f8dbab4e00217f/docs/user-guide/project-structure.md)
describes interfaces, feature modules, and infrastructure. It explicitly says
feature modules should not import one another except through `common`, and
infrastructure should not know particular features. The
[backend manifest](https://github.com/benavlabs/FastAPI-boilerplate/blob/2b6373d922bc993c7706c25a53f8dbab4e00217f/backend/pyproject.toml)
requires Python >=3.11; a Python 3.12 analysis environment is compatible with that
declared range, but the complete dependency install has not been tested.

**Small proposal:** start by checking imports from `backend/src/infrastructure/`
into `backend/src/modules/`. In an isolated evaluation, a deliberately injected
feature import should fail and its removal should restore the original result.
Then discuss enforcing feature-to-feature edges, preserving the documented
`common` exception. Analyze the backend as its own packaged project; the CLI is
a separate workspace member, not production backend code.

Do not infer that all files in infrastructure have one semantic role: its auth
routes are intentionally there. Full Taut onboarding must still account for
actual router, schema, model, test, and migration roles and feature expectations.

Unsent introduction:

```text
Hi, I'm the author of Taut, a Python architecture-policy checker. Fastro's
project-structure guide explicitly says infrastructure should not know about
feature modules, and feature modules should only share through common.

Would an optional check of the infrastructure-to-module boundary be useful?
I have a small public FastAPI example showing a forbidden import fail and its
one-line correction pass under an unchanged policy:
https://github.com/taewoo-dev/taut/tree/main/examples/architecture

I have not audited Fastro or found a confirmed violation. I'd start with your
existing documented rule and report setup effort and any analysis limitations
before proposing CI changes.
```

## Pilot 2: FastAPI Best Architecture

Source snapshot: `315f8a55ccfa4e2170c82f8f7db43bff46996133`.

The [README](https://github.com/fastapi-practices/fastapi-best-architecture/blob/315f8a55ccfa4e2170c82f8f7db43bff46996133/README.md)
maps API, schema, service, CRUD, and model layers. The source tree includes
`backend/app/admin/service/` and `backend/app/admin/crud/`. Its
[manifest](https://github.com/fastapi-practices/fastapi-best-architecture/blob/315f8a55ccfa4e2170c82f8f7db43bff46996133/pyproject.toml)
declares Python >=3.10. Keep its supported application versions; Taut itself can
run as a separate Python 3.12 check. This is manifest compatibility, not an
end-to-end installation result.

**Small proposal:** ask whether CRUD-to-service imports are forbidden, then
evaluate that agreed dependency direction in the admin package. The layer table
is evidence of structure, not proof of every allowed edge. Do not assume all
plugins and generated files have the same rules. Record exclusions with reasons,
and keep full-project setup separate from the narrow boundary demonstration.

Unsent introduction:

```text
Hi, I built Taut to check project-specific Python architecture rules. Your README
clearly separates API, service, CRUD, schema, and model responsibilities.

Is a CRUD-to-service import considered a violation in the admin package? If so,
I'd like to evaluate that one boundary as an optional example, using your own
conventions and without changing the application's supported Python versions.

This is the small reproducible demo of the checker:
https://github.com/taewoo-dev/taut/tree/main/examples/architecture

I have not verified your codebase with Taut yet. I would share the source commit,
configuration, setup issues, and exact results before suggesting adoption.
```

Follow the repository's [contribution guide](https://github.com/fastapi-practices/fastapi-best-architecture/blob/315f8a55ccfa4e2170c82f8f7db43bff46996133/CONTRIBUTING.md)
if the maintainer wants a patch.

## Pilot 3: GPT Researcher

Source snapshot: `6f998577d547b1e54ec662dac63583aa11e3b84b`.

Its [agent-facing architecture reference](https://github.com/assafelovic/gpt-researcher/blob/6f998577d547b1e54ec662dac63583aa11e3b84b/.claude/references/architecture.md)
describes a backend API layer above the reusable researcher, skills, and
configuration layers. The [manifest](https://github.com/assafelovic/gpt-researcher/blob/6f998577d547b1e54ec662dac63583aa11e3b84b/pyproject.toml)
requires Python >=3.11. It also has a frontend and code that accesses external
services; a complete audit must not mark those features absent to get a green result.

**Small proposal:** establish whether imports from reusable `gpt_researcher/`
modules into `backend/server/` are forbidden. If agreed, use that boundary for
the pilot and deliberately inject a reverse dependency in an isolated snapshot.
No LLM API calls are needed to demonstrate an import check. The architecture
diagram alone does not prove the intended import graph or an existing violation.

Unsent introduction:

```text
Hi, I'm building Taut, a checker for Python project conventions that coding
agents can otherwise drift away from. I noticed GPT Researcher already gives
agents a detailed .claude/references/architecture.md.

Would it be useful to check that the reusable gpt_researcher package doesn't
depend on backend/server? I'd first confirm that this is an intended boundary,
then evaluate a small static-check example without running research or API calls.

Here is a hand-authored FastAPI demo with recorded results:
https://github.com/taewoo-dev/taut/tree/main/examples/architecture

I haven't audited GPT Researcher or identified a confirmed violation. I'd report
onboarding effort and unsupported cases before recommending any CI gate.
```

## Evidence required before calling any pilot successful

Record the agreed convention, source commit, complete configured scope, policy
diff, setup duration, actual diagnostics, false positives, unsupported cases, and
maintainer feedback. A diagnostic on a deliberately injected import is a
demonstration, not a discovered bug. Full adoption requires complete assurance
and a passing check on the agreed real scope, followed by continued use.
