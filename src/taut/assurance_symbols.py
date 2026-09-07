from __future__ import annotations

from taut.configuration.assurance import FeatureExpectation
from taut.configuration.model import ProjectConfiguration
from taut.domain.assurance import AssuranceIssue
from taut.domain.ids import SymbolId
from taut.domain.snapshot import AnalysisSnapshot


def same_symbol(left: SymbolId, right: SymbolId) -> bool:
    """Compare policy symbols exactly after the analyzer has resolved aliases."""
    return left == right


def policy_symbol_issues(
    config: ProjectConfiguration, snapshot: AnalysisSnapshot
) -> tuple[AssuranceIssue, ...]:
    required = {
        name
        for name, expectation in config.assurance.features.items()
        if expectation is FeatureExpectation.REQUIRED
    }
    code = config.policy.code
    policy = config.policy
    configured: list[tuple[str, SymbolId, str]] = []
    if "schema" in required:
        configured.extend(("schema config", item, "value") for item in code.request_config_symbols)
        configured.extend(("schema config", item, "value") for item in code.response_config_symbols)
    if "dto" in required:
        configured.extend(("DTO base", item, "class") for item in code.dto_base_symbols)
    if "exception_registry" in required:
        configured.extend(("exception base", item, "class") for item in code.exception_base_symbols)
        configured.extend(
            ("error code enum", item, "class") for item in code.error_code_enum_symbols
        )
    if "transaction" in required:
        configured.extend(
            ("transaction provider", item, "callable")
            for item in policy.transaction_session_providers
        )
        configured.extend(
            ("transaction decorator", item, "callable")
            for item in policy.transaction_boundary_decorators
        )
        configured.extend(
            ("transaction context", item, "callable")
            for item in policy.transaction_boundary_contexts
        )
    if "external_calls" in required:
        configured.extend(
            ("external wrapper", item, "callable")
            for item in policy.boundaries.external_call_wrappers
        )

    # Project-owned extension symbols remain part of the assurance contract after
    # onboarding. Third-party symbols are intentionally excluded below because
    # their definitions are outside the analyzed source graph.
    configured.extend(
        ("abstract exception", item, "class") for item in code.abstract_exception_symbols
    )
    configured.extend(
        ("reserved error code", item, "value") for item in code.reserved_error_code_symbols
    )
    configured.extend(("generic schema base", item, "class") for item in code.generic_schema_bases)
    configured.extend(
        ("test HTTP fixture", item, "callable") for item in code.test_http_fixture_symbols
    )
    configured.extend(
        ("raw query wrapper", item, "callable") for item in policy.boundaries.raw_query_wrappers
    )
    configured.extend(
        ("adapter implementation", item, "class")
        for item in policy.boundaries.adapter_implementation_symbols
    )
    configured.extend(
        ("settings constructor", item, "callable")
        for item in policy.boundaries.settings_constructors
    )
    configured.extend(
        ("enum policy exception", item, "class")
        for item in (
            code.uppercase_enum_exceptions
            | code.non_str_enum_exceptions
            | code.native_enum_false_exceptions
            | code.native_enum_no_constraint_exceptions
        )
    )
    configured.extend(
        ("session type", item, "class") for item in policy.boundaries.session_type_symbols
    )
    configured.extend(
        ("configured policy call", item, "callable")
        for item in (
            *policy.boundaries.adapter_forbidden_calls,
            *policy.boundaries.database_statement_calls,
            *policy.boundaries.transport_exception_calls,
            *policy.boundaries.dependency_injection_calls,
            *policy.boundaries.external_client_constructors,
            *policy.boundaries.raw_sql_calls,
            *policy.boundaries.schema_sql_parent_calls,
            *policy.boundaries.http_timeout_calls,
            *policy.boundaries.logged_external_calls,
            *code.raw_test_http_calls,
            *code.raw_test_http_client_constructors,
        )
    )

    top_levels = {module_id.value.split(".", 1)[0] for module_id in snapshot.modules}
    classes = {item.symbol_id for module in snapshot.modules.values() for item in module.classes}
    functions = {
        item.symbol_id for module in snapshot.modules.values() for item in module.functions
    }
    fields = {item.symbol_id for module in snapshot.modules.values() for item in module.fields}
    observed = (
        classes
        | functions
        | fields
        | {
            ref.symbol
            for module in snapshot.modules.values()
            for call in module.calls
            for ref in (call.ref, *call.enclosing_contexts)
            if ref.symbol is not None
        }
        | {
            decorator.ref.symbol
            for module in snapshot.modules.values()
            for decorator in module.decorators
            if decorator.ref.symbol is not None
        }
    )
    issues: list[AssuranceIssue] = []
    unique_configured = {
        (symbol, expected_kind): label for label, symbol, expected_kind in configured
    }
    for (symbol, expected_kind), label in sorted(
        unique_configured.items(), key=lambda item: (item[0][0], item[0][1])
    ):
        # Taut cannot inspect definitions owned by dependencies. Provider facts and
        # actual resolved uses cover those; liveness checks apply to first-party
        # namespaces only.
        if symbol.value.split(".", 1)[0] not in top_levels:
            continue
        if symbol not in observed:
            issues.append(
                AssuranceIssue(
                    "POLICY_SYMBOL_UNRESOLVED",
                    (
                        "Could not resolve the exact symbol used to activate this policy in "
                        "the source code."
                    ),
                    symbol.value,
                    f"Set {label} to an existing fully qualified symbol.",
                )
            )
            continue
        correct = (
            symbol in classes
            if expected_kind == "class"
            else symbol in fields
            if expected_kind == "value"
            else symbol in functions or symbol in classes
        )
        if not correct:
            issues.append(
                AssuranceIssue(
                    "POLICY_SYMBOL_KIND_MISMATCH",
                    "The policy symbol kind does not match the required contract.",
                    symbol.value,
                    f"Set {label} to a symbol of kind {expected_kind}.",
                )
            )
    return tuple(issues)
