"""Conservative simplification for Taut's existing fnmatchcase semantics."""


def compact_patterns(patterns: tuple[str, ...]) -> tuple[str, ...]:
    # fnmatchcase's * already crosses /, so x/*.py includes x/**/*.py.
    # Do not infer coverage from the currently existing files.
    def redundant(pattern: str) -> bool:
        for suffix in ("*.py", "*.pyi"):
            marker = f"**/{suffix}"
            if pattern == marker or pattern.endswith(f"/{marker}"):
                shorter = pattern[: -len(marker)] + suffix
                if shorter in patterns:
                    return True
        return False

    return tuple(dict.fromkeys(pattern for pattern in patterns if not redundant(pattern)))
