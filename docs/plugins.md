# Plugin authoring

pytaut discovers rule packs through the `taut.rule_packs.v1` entry-point group, fact providers
through `taut.fact_providers.v1`, and init framework hints through
`taut.onboarding_contributors.v1`. Plugin code should import authoring contracts only
from `taut.plugins.v1` (or the equivalent `taut.plugins` facade) and semantic contracts from
`taut.semantic.v1`; concrete AST analyzer modules are not part of the plugin API.

## Minimal rule pack

The following project-level rule is deliberately small, but it is a complete installable pack.

```python
# src/example_taut/plugin.py
from dataclasses import dataclass

from taut.plugins.v1 import (
    AnalysisStage,
    AnalysisSnapshot,
    AssuranceAuditorV1,
    AssuranceIssue,
    ChangeImpact,
    PolicyContext,
    ProjectConfiguration,
    RuleDefinition,
    RuleEvaluation,
    RuleId,
    RulePackV1,
    RuleRegistry,
    RuleRequirements,
    RuleTarget,
    RuleTargetRef,
    RuleVerdict,
)

RULE_ID = RuleId("EXAMPLE001")


@dataclass(frozen=True)
class ExampleRule:
    def evaluate(
        self, target: RuleTargetRef, context: PolicyContext
    ) -> RuleEvaluation:
        del context
        return RuleEvaluation(RULE_ID, target, RuleVerdict.PASS, ())


@dataclass(frozen=True)
class ExampleAssuranceAuditor:
    id: str = "example.rules.assurance"
    version: str = "1"
    audited_rules: frozenset[str] = frozenset({RULE_ID.value})

    def audit(
        self, snapshot: AnalysisSnapshot, config: ProjectConfiguration
    ) -> tuple[AssuranceIssue, ...]:
        # Return AssuranceIssue values when the pack's activation prerequisites are missing.
        del snapshot, config
        return ()


def create_pack() -> RulePackV1:
    definition = RuleDefinition(
        id=RULE_ID,
        behavior_version=1,
        title="Example project contract",
        help="Explain the repository-specific contract and remediation.",
        target=RuleTarget.PROJECT,
        requirements=RuleRequirements(
            capabilities=frozenset(),
            minimum_stage=AnalysisStage.DISCOVERED,
            needs_resolved_symbols=False,
            needs_complete_project=False,
        ),
        change_impact=ChangeImpact.PROJECT,
        implementation=ExampleRule(),
        compliant_fixtures=("value = 1",),
        violation_fixtures=("value = 0",),
    )
    return RulePackV1(
        id="example.rules",
        version="1.0.0",
        registry=RuleRegistry.build((definition,)),
        assurance_auditor=ExampleAssuranceAuditor(),
    )
```

Register the factory in the plugin package's `pyproject.toml`:

```toml
[project]
name = "example-taut-rules"
version = "1.0.0"
dependencies = ["pytaut>=0.3,<0.4"]

[project.entry-points."taut.rule_packs.v1"]
"example.rules" = "example_taut.plugin:create_pack"
```

Then enable it in the checked repository:

```toml
[tool.taut]
schema_version = 5
packs = ["taut.backend", "example.rules"]

[tool.taut.rules]
EXAMPLE001 = "enforced"
```

Strict v4 projects also require every rule pack to expose an `AssuranceAuditorV1` whose
`audited_rules` exactly covers the pack registry. This prevents a third-party enforced rule from
silently becoming non-applicable because its setup contract was omitted. Adoption projects may
use `strict = false` while adding that auditor.

`taut config validate .` loads every declared pack and provider, rejects duplicate rule IDs or
unknown plugins, and validates rule configuration against the resulting registry. Pack and
provider versions, required capabilities, implementation identities, entry points, and Python
major/minor versions participate in cache or daemon compatibility, so an extension upgrade cannot
silently reuse an earlier decision.

Fact providers implement `FactProviderV1` or `IncrementalFactProviderV1`, declare versioned
`CapabilitySpec` values, and register a zero-argument factory under
`taut.fact_providers.v1`. A rule lists those capability IDs in `RuleRequirements.capabilities`;
missing or failed capabilities produce explicit coverage rather than an unchecked rule execution.

## Contribute framework detection to init

A fact-provider plugin can also teach `taut init` which imports activate it. This contract only
maps imported top-level modules to a provider ID; it cannot silently add roles, allow edges, feature
decisions, or exceptions.

```python
from dataclasses import dataclass

from taut.plugins.v1 import OnboardingFrameworkSpec


@dataclass(frozen=True)
class ExampleOnboarding:
    id: str = "example.orm.onboarding"
    version: str = "1"
    frameworks: tuple[OnboardingFrameworkSpec, ...] = (
        OnboardingFrameworkSpec("example.orm", ("exampleorm",)),
    )
```

```toml
[project.entry-points."taut.onboarding_contributors.v1"]
"example.orm.onboarding" = "example_taut.plugin:ExampleOnboarding"
```

Import roots must be unique across built-in and installed contributors. Duplicate ownership or an
invalid contribution stops onboarding explicitly.
