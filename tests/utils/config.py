from __future__ import annotations

from taut.configuration.assurance import BUILTIN_ASSURANCE_FEATURES


def assurance_toml(*, pyproject: bool = False, required: tuple[str, ...] = ()) -> str:
    prefix = "tool.taut." if pyproject else ""
    lines = [f"[{prefix}assurance.features]"]
    required_set = set(required)
    lines.extend(
        f'{feature} = "{"required" if feature in required_set else "absent"}"'
        for feature in BUILTIN_ASSURANCE_FEATURES
    )
    return "\n".join(lines)
