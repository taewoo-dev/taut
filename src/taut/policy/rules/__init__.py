from __future__ import annotations

from taut.configuration.rule_standard import BUILTIN_RULE_LEVELS
from taut.policy.registry import RuleRegistry as _RuleRegistry
from taut.policy.rules.api_contracts import api_rule_definitions as _api_rule_definitions
from taut.policy.rules.architecture import (
    architecture_rule_definitions as _architecture_rule_definitions,
)
from taut.policy.rules.async_safety import (
    async_safety_rule_definition as _async_safety_rule_definition,
)
from taut.policy.rules.boundary import (
    boundary_rule_definition as _boundary_rule_definition,
)
from taut.policy.rules.catalog_coverage import (
    catalog_coverage_rule_definition as _catalog_coverage_rule_definition,
)
from taut.policy.rules.classification import (
    classification_rule_definition as _classification_rule_definition,
)
from taut.policy.rules.construction_boundaries import (
    construction_rule_definitions as _construction_rule_definitions,
)
from taut.policy.rules.conventions import (
    convention_rule_definitions as _convention_rule_definitions,
)
from taut.policy.rules.enums import enum_rule_definition as _enum_rule_definition
from taut.policy.rules.exceptions import (
    exception_rule_definition as _exception_rule_definition,
)
from taut.policy.rules.external_calls import (
    external_call_rule_definitions as _external_call_rule_definitions,
)
from taut.policy.rules.ignore_audit import (
    ignore_audit_rule_definition as _ignore_audit_rule_definition,
)
from taut.policy.rules.layer_boundaries import (
    layer_boundary_rule_definitions as _layer_boundary_rule_definitions,
)
from taut.policy.rules.model_shapes import (
    model_shape_rule_definitions as _model_shape_rule_definitions,
)
from taut.policy.rules.persistence import (
    persistence_rule_definitions as _persistence_rule_definitions,
)
from taut.policy.rules.response_mapping import (
    response_mapping_rule_definition as _response_mapping_rule_definition,
)
from taut.policy.rules.responsibility_boundaries import (
    responsibility_boundary_rule_definitions as _responsibility_boundary_rule_definitions,
)
from taut.policy.rules.runtime_safety import (
    runtime_rule_definitions as _runtime_rule_definitions,
)
from taut.policy.rules.security import (
    security_rule_definition as _security_rule_definition,
)
from taut.policy.rules.session import session_rule_definitions as _session_rule_definitions
from taut.policy.rules.test_boundaries import (
    test_boundary_rule_definitions as _test_boundary_rule_definitions,
)
from taut.policy.rules.time_access import time_rule_definition as _time_rule_definition
from taut.policy.rules.transaction import (
    multi_write_atomicity_rule_definition as _multi_write_atomicity_rule_definition,
)
from taut.policy.rules.transaction import (
    transaction_rule_definition as _transaction_rule_definition,
)

__all__ = ["builtin_rule_registry"]


def builtin_rule_registry() -> _RuleRegistry:
    registry = _RuleRegistry.build(
        (
            _classification_rule_definition(),
            _time_rule_definition(),
            _transaction_rule_definition(),
            _multi_write_atomicity_rule_definition(),
            *_session_rule_definitions(),
            *_convention_rule_definitions(),
            _boundary_rule_definition(),
            *_responsibility_boundary_rule_definitions(),
            *_layer_boundary_rule_definitions(),
            *_construction_rule_definitions(),
            *_test_boundary_rule_definitions(),
            *_external_call_rule_definitions(),
            *_architecture_rule_definitions(),
            *_runtime_rule_definitions(),
            _async_safety_rule_definition(),
            _security_rule_definition(),
            _catalog_coverage_rule_definition(),
            *_model_shape_rule_definitions(),
            *_api_rule_definitions(),
            _response_mapping_rule_definition(),
            _enum_rule_definition(),
            *_persistence_rule_definitions(),
            _exception_rule_definition(),
            _ignore_audit_rule_definition(),
        )
    )
    actual = {
        rule_id: definition.default_level for rule_id, definition in registry.definitions.items()
    }
    if actual != dict(BUILTIN_RULE_LEVELS.items()):
        raise ValueError("built-in rules do not match the built-in rule levels")
    return registry
