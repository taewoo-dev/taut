# Documentation

Start with the [setup guide](getting-started.md) or run the
[FastAPI example](../examples/architecture/README.md).
These documents describe pytaut 0.10.0, configuration schema v5, and Python 3.12+.

## Using Taut

- [Getting started](getting-started.md): installation, policy setup, agent-assisted setup, and CI.
- [Reference](reference.md): CLI commands, configuration, rules, and extension contracts.
- [Configuration conventions](configuration-conventions.md): file roles, automatic classification, and policy simplification.
- [Detection scope](detection-quality.md): what results establish, known limits, and incremental adoption.
- [Migration guide](../MIGRATION.md): upgrading existing configurations.
- [Cache and daemon operations](operations.md): execution modes, lifecycle, and security boundaries.
- [Performance measurement](performance.md): reproducible benchmarks and result interpretation.

## Examples and development

- [Runnable architecture example](../examples/architecture/README.md): before/after code and verified results.
- [Demo and visual assets](launch/README.md): media, logos, and reproduction commands.
- [Plugin development](plugins.md): public rule-pack and fact-provider contracts.
- [System architecture](architecture/taut-system-architecture.html): interactive component and analysis-flow map.

Run `bash scripts/test.sh` from the repository root for the static checks,
tests, coverage, package build, and installed-wheel smoke test.
