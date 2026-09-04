"""Validated repository-specific policy decisions supplied during onboarding."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import cast

from taut.configuration.assurance import AssuranceAssertion
from taut.configuration.manifest import Role, Zone
from taut.domain.ids import ModuleId, SymbolId
from taut.loading.errors import PolicyConfigError
from taut.loading.policy_extensions import KNOWN_ZONES
from taut.project_observation import observe_path

_CODE_SYMBOL_KEYS = frozenset(
    {
        "request_config_symbols",
        "response_config_symbols",
        "exception_base_symbols",
        "abstract_exception_symbols",
        "error_code_enum_symbols",
        "reserved_error_code_symbols",
        "dto_base_symbols",
        "exception_code_argument_names",
        "exception_code_field_names",
        "test_http_fixture_symbols",
    }
)


@dataclass(frozen=True, order=True)
class InitExclusion:
    patterns: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class InitPolicyAnswers:
    zones: tuple[tuple[str, tuple[str, ...]], ...] = ()
    exclusions: tuple[InitExclusion, ...] = ()
    code_conventions: tuple[tuple[str, tuple[str, ...]], ...] = ()
    response_mapper_name: str = "from_internal"
    response_mapper_explicit: bool = False
    transaction_roles: tuple[str, ...] = ()
    transaction_participants: tuple[str, ...] = ()
    session_providers: tuple[str, ...] = ()
    boundary_decorators: tuple[str, ...] = ()
    boundary_contexts: tuple[str, ...] = ()
    provider_item_types: tuple[tuple[str, str], ...] = ()
    external_modules: tuple[str, ...] = ()
    logged_calls: tuple[str, ...] = ()
    external_wrappers: tuple[str, ...] = ()
    shared_enum_modules: tuple[str, ...] = ()
    assertions: tuple[AssuranceAssertion, ...] = ()

    def code_values(self, key: str) -> tuple[str, ...]:
        return dict(self.code_conventions).get(key, ())


def answer_policy(answers: dict[str, object] | None) -> InitPolicyAnswers:
    if answers is None:
        return InitPolicyAnswers()
    zones = _zones(answers.get("zones"))
    exclusions = _exclusions(answers.get("exclusions"))
    raw_policy = answers.get("policy", {})
    policy = _table(raw_policy, "policy")
    _reject_unknown(policy, {"code_conventions", "transaction", "external", "enum"}, "policy")

    code = _table(policy.get("code_conventions", {}), "policy.code_conventions")
    _reject_unknown(
        code,
        _CODE_SYMBOL_KEYS | {"response_mapper_name"},
        "policy.code_conventions",
    )
    mapper = code.get("response_mapper_name", "from_internal")
    if not isinstance(mapper, str) or not mapper.isidentifier():
        raise PolicyConfigError(
            "policy.code_conventions.response_mapper_name must be a Python identifier"
        )
    code_values = tuple(
        sorted(
            (key, _symbols(value, f"policy.code_conventions.{key}"))
            for key, value in code.items()
            if key != "response_mapper_name"
        )
    )

    transaction = _table(policy.get("transaction", {}), "policy.transaction")
    _reject_unknown(
        transaction,
        {
            "owner_roles",
            "participant_roles",
            "session_providers",
            "provider_item_types",
            "boundary_decorators",
            "boundary_contexts",
        },
        "policy.transaction",
    )
    owners = _roles(transaction.get("owner_roles", []), "policy.transaction.owner_roles")
    participants = _roles(
        transaction.get("participant_roles", []), "policy.transaction.participant_roles"
    )
    providers = _symbols(
        transaction.get("session_providers", []), "policy.transaction.session_providers"
    )
    boundary_decorators = _symbols(
        transaction.get("boundary_decorators", []),
        "policy.transaction.boundary_decorators",
    )
    boundary_contexts = _symbols(
        transaction.get("boundary_contexts", []),
        "policy.transaction.boundary_contexts",
    )
    provider_types = _symbol_mapping(
        transaction.get("provider_item_types", {}), "policy.transaction.provider_item_types"
    )
    if set(dict(provider_types)).difference(providers):
        raise PolicyConfigError(
            "init policy.transaction.provider_item_types keys must also be session_providers"
        )

    external = _table(policy.get("external", {}), "policy.external")
    _reject_unknown(external, {"modules", "logged_calls", "wrappers"}, "policy.external")
    modules = _modules(external.get("modules", []), "policy.external.modules")
    logged = _symbols(external.get("logged_calls", []), "policy.external.logged_calls")
    wrappers = _symbols(external.get("wrappers", []), "policy.external.wrappers")

    enum = _table(policy.get("enum", {}), "policy.enum")
    _reject_unknown(enum, {"shared_modules"}, "policy.enum")
    shared_modules = _modules(enum.get("shared_modules", []), "policy.enum.shared_modules")
    assurance = _table(answers.get("assurance", {}), "assurance")
    _reject_unknown(assurance, {"assertions"}, "assurance")
    assertions = _assertions(assurance.get("assertions", []))
    return InitPolicyAnswers(
        zones=zones,
        exclusions=exclusions,
        code_conventions=code_values,
        response_mapper_name=mapper,
        response_mapper_explicit="response_mapper_name" in code,
        transaction_roles=owners,
        transaction_participants=participants,
        session_providers=providers,
        boundary_decorators=boundary_decorators,
        boundary_contexts=boundary_contexts,
        provider_item_types=provider_types,
        external_modules=modules,
        logged_calls=logged,
        external_wrappers=wrappers,
        shared_enum_modules=shared_modules,
        assertions=assertions,
    )


def missing_policy_decisions(
    expectations: dict[str, str], policy: InitPolicyAnswers
) -> tuple[tuple[str, str], ...]:
    missing: list[tuple[str, str]] = []
    if expectations["schema"] == "required" and not (
        policy.code_values("request_config_symbols")
        or policy.code_values("response_config_symbols")
    ):
        missing.append(("schema", "request_config_symbols or response_config_symbols"))
    if expectations["exception_registry"] == "required" and not (
        policy.code_values("exception_base_symbols")
        and policy.code_values("error_code_enum_symbols")
    ):
        missing.append(("exception_registry", "exception_base_symbols and error_code_enum_symbols"))
    if expectations["enum"] == "required" and not policy.shared_enum_modules:
        missing.append(("enum", "shared_modules"))
    if expectations["transaction"] == "required" and not (
        policy.transaction_roles
        and (policy.session_providers or policy.boundary_decorators or policy.boundary_contexts)
    ):
        missing.append(
            (
                "transaction",
                "owner_roles and session_providers, boundary_decorators, or boundary_contexts",
            )
        )
    return tuple(missing)


def effective_zones(
    paths: tuple[str, ...], policy: InitPolicyAnswers
) -> dict[str, tuple[str, ...]]:
    if policy.zones:
        return dict(policy.zones)
    observed = {
        name: tuple(path for path in paths if observe_path(path).zone == name)
        for name in ("test", "migration", "script")
    }
    return {name: items for name, items in observed.items() if items}


def render_policy_lines(policy: InitPolicyAnswers) -> tuple[str, ...]:
    lines: list[str] = []
    for exclusion in policy.exclusions:
        lines.extend(
            (
                "",
                "[[tool.taut.exclusions]]",
                f"patterns = {_toml_array(exclusion.patterns)}",
                f"reason = {json.dumps(exclusion.reason)}",
            )
        )
    if policy.code_conventions or policy.response_mapper_name != "from_internal":
        lines.extend(("", "[tool.taut.code_conventions]"))
        lines.append(f"response_mapper_name = {json.dumps(policy.response_mapper_name)}")
        for name, values in policy.code_conventions:
            lines.append(f"{name} = {_toml_array(values)}")
    if (
        policy.transaction_roles
        or policy.session_providers
        or policy.boundary_decorators
        or policy.boundary_contexts
    ):
        lines.extend(("", "[tool.taut.transaction]"))
        lines.append(f"owner_roles = {_toml_array(policy.transaction_roles)}")
        if policy.transaction_participants:
            lines.append(f"participant_roles = {_toml_array(policy.transaction_participants)}")
        lines.append(f"session_providers = {_toml_array(policy.session_providers)}")
        if policy.boundary_decorators:
            lines.append(f"boundary_decorators = {_toml_array(policy.boundary_decorators)}")
        if policy.boundary_contexts:
            lines.append(f"boundary_contexts = {_toml_array(policy.boundary_contexts)}")
        if policy.provider_item_types:
            lines.extend(("", "[tool.taut.transaction.provider_item_types]"))
            for provider, item_type in policy.provider_item_types:
                lines.append(f"{json.dumps(provider)} = {json.dumps(item_type)}")
    if policy.external_modules or policy.logged_calls or policy.external_wrappers:
        lines.extend(("", "[tool.taut.external]"))
        if policy.external_modules:
            lines.append(f"modules = {_toml_array(policy.external_modules)}")
        lines.append(f"logged_calls = {_toml_array(policy.logged_calls)}")
        lines.append(f"wrappers = {_toml_array(policy.external_wrappers)}")
    if policy.shared_enum_modules:
        lines.extend(("", "[tool.taut.enum]"))
        lines.append(f"shared_modules = {_toml_array(policy.shared_enum_modules)}")
    return tuple(lines)


def _toml_array(values: tuple[str, ...]) -> str:
    return "[" + ", ".join(json.dumps(value) for value in values) + "]"


def validated_patterns(raw: object, field: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(raw, list) or (not raw and not allow_empty):
        raise PolicyConfigError(f"init answers.{field} must be a non-empty string array")
    raw_values = cast(list[object], raw)
    if not all(isinstance(item, str) and item.strip() for item in raw_values):
        raise PolicyConfigError(f"init answers.{field} must be a string array")
    values = tuple(cast(list[str], raw))
    if len(values) != len(set(values)):
        raise PolicyConfigError(f"duplicate init patterns in {field}")
    return values


def _zones(raw: object) -> tuple[tuple[str, tuple[str, ...]], ...]:
    if raw is None:
        return ()
    table = _table(raw, "zones")
    unknown = set(table).difference(KNOWN_ZONES)
    if unknown:
        raise PolicyConfigError(f"unknown init zones: {', '.join(sorted(unknown))}")
    values = tuple(
        sorted((name, _strings(patterns, f"zones.{name}")) for name, patterns in table.items())
    )
    if any(not patterns for _, patterns in values):
        raise PolicyConfigError("init zones require at least one pattern")
    for name, _ in values:
        Zone(name)
    return values


def _exclusions(raw: object) -> tuple[InitExclusion, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise PolicyConfigError("init answers.exclusions must be an array")
    values: list[InitExclusion] = []
    for index, item in enumerate(cast(list[object], raw)):
        table = _table(item, f"exclusions[{index}]")
        _reject_unknown(table, {"patterns", "reason"}, f"exclusions[{index}]")
        patterns = _strings(table.get("patterns"), f"exclusions[{index}].patterns")
        reason = table.get("reason")
        if not patterns or not isinstance(reason, str) or not reason.strip():
            raise PolicyConfigError("init exclusions require non-empty patterns and reason")
        values.append(InitExclusion(patterns, reason.strip()))
    if len(values) != len(set(values)):
        raise PolicyConfigError("duplicate init exclusion")
    return tuple(sorted(values))


def _roles(raw: object, label: str) -> tuple[str, ...]:
    values = _strings(raw, label)
    for value in values:
        Role(value)
    return values


def _symbols(raw: object, label: str) -> tuple[str, ...]:
    values = _strings(raw, label)
    for value in values:
        SymbolId(value)
    return values


def _modules(raw: object, label: str) -> tuple[str, ...]:
    values = _strings(raw, label)
    for value in values:
        ModuleId(value)
    return values


def _symbol_mapping(raw: object, label: str) -> tuple[tuple[str, str], ...]:
    table = _table(raw, label)
    values: list[tuple[str, str]] = []
    for key, value in table.items():
        if not isinstance(value, str) or not value.strip():
            raise PolicyConfigError(f"{label} values must be non-empty symbol strings")
        SymbolId(key)
        SymbolId(value)
        values.append((key, value))
    return tuple(sorted(values))


def _assertions(raw: object) -> tuple[AssuranceAssertion, ...]:
    if not isinstance(raw, list):
        raise PolicyConfigError("init answers.assurance.assertions must be an array")
    values: list[AssuranceAssertion] = []
    for index, value in enumerate(cast(list[object], raw)):
        table = _table(value, f"assurance.assertions[{index}]")
        _reject_unknown(
            table,
            {"domain", "kind", "target", "state", "reason"},
            f"assurance.assertions[{index}]",
        )
        try:
            values.append(
                AssuranceAssertion(
                    domain=_required_string(table.get("domain"), "assertion domain"),
                    kind=_required_string(table.get("kind"), "assertion kind"),
                    target=_required_string(table.get("target"), "assertion target"),
                    state=_required_string(table.get("state"), "assertion state"),
                    reason=_required_string(table.get("reason"), "assertion reason"),
                )
            )
        except ValueError as error:
            raise PolicyConfigError(f"invalid init assurance assertion: {error}") from error
    if len(values) != len(set(values)):
        raise PolicyConfigError("duplicate init assurance assertion")
    return tuple(sorted(values))


def _required_string(raw: object, label: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise PolicyConfigError(f"init {label} must be a non-empty string")
    return raw.strip()


def _strings(raw: object, label: str) -> tuple[str, ...]:
    if not isinstance(raw, list):
        raise PolicyConfigError(f"{label} must be an array of non-empty strings")
    values = cast(list[object], raw)
    if not all(isinstance(value, str) and value.strip() for value in values):
        raise PolicyConfigError(f"{label} must be an array of non-empty strings")
    result = tuple(sorted(set(cast(list[str], values))))
    if len(result) != len(values):
        raise PolicyConfigError(f"{label} must contain unique strings")
    return result


def _table(raw: object, label: str) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise PolicyConfigError(f"init answers.{label} must be an object")
    mapping = cast(dict[object, object], raw)
    if not all(isinstance(key, str) for key in mapping):
        raise PolicyConfigError(f"init answers.{label} must be an object")
    return {cast(str, key): value for key, value in mapping.items()}


def _reject_unknown(
    values: dict[str, object], known: set[str] | frozenset[str], label: str
) -> None:
    unknown = set(values).difference(known)
    if unknown:
        raise PolicyConfigError(f"unknown init {label} keys: {', '.join(sorted(unknown))}")
