from __future__ import annotations

IGNORED_DIRECTORY_NAMES = frozenset(
    {
        ".bzr",
        ".direnv",
        ".eggs",
        ".git",
        ".git-rewrite",
        ".hg",
        ".ipynb_checkpoints",
        ".mypy_cache",
        ".nox",
        ".pants.d",
        ".pyenv",
        ".pytest_cache",
        ".pytype",
        ".research",
        ".ruff_cache",
        ".svn",
        ".taut_cache",
        ".tox",
        ".venv",
        ".vscode",
        "__pycache__",
        "__pypackages__",
        "_build",
        "buck-out",
        "build",
        "dist",
        "node_modules",
        "site-packages",
        "venv",
    }
)

# Root and nested forms are both intentional: fnmatch does not make a leading
# ``**/`` match a root-level directory consistently across all callers.
DEFAULT_EXCLUDE_PATTERNS = tuple(
    pattern
    for name in sorted(IGNORED_DIRECTORY_NAMES)
    for pattern in (f"{name}/**", f"**/{name}/**")
)
