from __future__ import annotations

from taut.configuration.assurance import AssuranceConfiguration
from taut.configuration.catalog import Effect, EffectCatalog
from taut.configuration.effective_policy import EffectivePolicy, SecurityPolicy
from taut.configuration.manifest import ProjectManifest, Role, Zone
from taut.configuration.model import ProjectConfiguration
from taut.configuration.rule_standard import BUILTIN_RULE_LEVELS
from taut.configuration.source_scope import DEFAULT_EXCLUDE_PATTERNS
from taut.domain.evaluations import RuleSetting
from taut.domain.frozen import FrozenMap
from taut.domain.location import ConfigLocation, ConfigPath, ProjectPath
from taut.loading.builtin_catalog import builtin_catalog_entries

_DEFAULT_CONFIG_PATH = ConfigPath("pyproject.toml")


def default_project_configuration(
    source: ProjectPath | ConfigPath = _DEFAULT_CONFIG_PATH,
) -> ProjectConfiguration:
    """Stable in-memory defaults for tests and embedding."""
    location = ConfigLocation(source)
    settings = FrozenMap(
        (rule_id, RuleSetting(level, FrozenMap())) for rule_id, level in BUILTIN_RULE_LEVELS.items()
    )
    security = SecurityPolicy(
        allowed_roles=FrozenMap(
            (
                (
                    Effect.SECURITY_ENVIRONMENT,
                    frozenset({Role("configuration"), Role("bootstrap")}),
                ),
                (
                    Effect.SECURITY_SECRET,
                    frozenset({Role("configuration"), Role("bootstrap"), Role("adapter")}),
                ),
                (Effect.SECURITY_TOKEN, frozenset({Role("security"), Role("adapter")})),
            )
        ),
        risky_symbol_prefixes=(
            "httpx.AsyncClient.",
            "httpx.Client.",
            "requests.",
            "subprocess.",
        ),
    )
    return ProjectConfiguration(
        include=("*.py", "**/*.py", "*.pyi", "**/*.pyi"),
        exclude=DEFAULT_EXCLUDE_PATTERNS,
        source_roots=(ProjectPath("."),),
        manifest=ProjectManifest((), (), Zone("prod"), location),
        catalog=EffectCatalog(
            FrozenMap((entry.symbol, entry) for entry in builtin_catalog_entries())
        ),
        policy=EffectivePolicy(
            rules=settings,
            allowed_imports=FrozenMap(),
            transaction_owner_roles=frozenset(),
            security=security,
        ),
        force_include=(),
        schema_version=5,
        strict=False,
        assurance=AssuranceConfiguration.non_strict_default(),
    )
