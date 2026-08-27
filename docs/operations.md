# Cache and daemon operations

Since pytaut 0.2.0, the engine has two acceleration layers. The disk cache speeds up separate CLI
processes. The daemon keeps one analyzed project resident and incrementally updates
it for tight local development loops. Both layers are optional and preserve the
same stdout, stderr, and exit code as the canonical pipeline.

## Recommended modes

| Environment | Command | Reason |
|---|---|---|
| CI or release gate | `taut check . --daemon never` | One isolated process; disk cache remains available |
| canonical cold diagnosis | `taut check . --daemon never --no-cache` | Rebuild every analysis layer |
| editor or local loop | `taut check . --daemon auto` | Start or reuse the project daemon |
| daemon-required integration | `taut check . --daemon required` | Fail instead of falling back if the daemon is unavailable |

`auto` falls back to the local pipeline if daemon startup or communication fails.
`required` reports that failure. The default remains `never`, so adopting the daemon
does not silently introduce a resident process.

## Lifecycle

```bash
taut daemon start /path/to/project
taut daemon status /path/to/project
taut daemon restart /path/to/project
taut daemon stop /path/to/project
```

One daemon owns exactly one canonical project root. Startup is serialized, stale
or incompatible status is rejected, and a daemon exits after 30 minutes without a
request. Updating pytaut changes the recorded version and causes incompatible state
to be replaced on the next start. Installing, removing, upgrading, or changing the
entry point of a rule pack or fact provider also invalidates daemon compatibility.

## Disk cache

The default directory is `<project>/.taut_cache`; configure another project-relative
directory under `[tool.taut.cache]`, pass `--cache-dir`, or disable reads and writes
with `--no-cache`.

```toml
[tool.taut.cache]
enabled = true
directory = ".cache/taut"
```

```bash
taut cache stats /path/to/project
taut cache clean /path/to/project
```

`stats` and `clean` load the same project configuration and therefore follow its
configured directory. `--cache-dir` overrides that location. Asking for statistics
on a cache that does not exist reports zero without creating a directory. Cache data
is disposable. Cleaning it cannot remove source or configuration files; the next
check rebuilds it.

## Security model

- Daemon status and startup-lock directories are owner-only (`0700`), and status
  files are regular owner-only files (`0600`) on POSIX systems.
- Requests use a random per-instance token and are bound to the canonical project,
  protocol, and pytaut version.
- Fast module bundles and rendered report entries are HMAC-SHA-256 authenticated with
  a 32-byte owner-only key stored outside the project cache. They are also bound to
  project, adapter, resolver, source/module identity, plugin decision contract,
  resolved rendering options, and Python major/minor version as applicable.
- Bundle decoding accepts only a closed set of pytaut domain types. Authentication
  or decoding uncertainty is always a cache miss.

Do not copy `.taut_cache` between users or treat it as an artifact. Add it to the
target repository's ignore rules when the repository uses the default directory.
