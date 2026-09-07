from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass

from taut.configuration.effective_policy import EffectivePolicy, PolicyApproval
from taut.configuration.manifest import ClassificationIndex
from taut.domain.diagnostics import Diagnostic, FindingDisposition
from taut.domain.evaluations import RuleLevel
from taut.domain.findings import EvidenceItem, Finding, FindingSource
from taut.domain.frozen import FrozenMap
from taut.domain.ids import FindingFingerprint, RuleId, SymbolId
from taut.domain.ignores import InlineIgnore
from taut.domain.issues import EngineIssue
from taut.domain.reports import ApprovalAudit, IgnoreAudit

_IGNORE_RULE_ID = RuleId("IGNORE001")
_SUPPRESSION_APPROVAL_KINDS = frozenset(
    {"allow", "entrypoint", "factory", "lazy_import", "security_wrapper"}
)

_MESSAGES = {
    "role.unassigned": "No role is assigned to this source file.",
    "time.direct_access": "Direct call to unapproved clock function {symbol}.",
    "transaction.outside_owner": "Role {role} calls {effect} outside the transaction owner.",
    "session.outside_owner": (
        "Role {role} calls DB session provider {provider} outside the transaction owner."
    ),
    "session.nested": "DB session provider {provider} is called inside another session.",
    "session.service_parameter": "Service function {symbol} accepts a DB session argument.",
    "session.participant_owns_transaction": (
        "Transaction participant {symbol} performs owner operation {operation}."
    ),
    "boundary.forbidden_import": "Role {role} imports forbidden module {imported} ({boundary}).",
    "architecture.import_direction": (
        "Role {source_role} imports {target_module} from disallowed role {target_role}."
    ),
    "architecture.import_cycle": "Internal import cycle: {cycle}",
    "import.local_import": "Import of {imported} inside a function.",
    "import.relative_import": "Relative import of {imported}.",
    "size.file_too_large": "File has {lines} lines, exceeding the limit of {maximum}.",
    "boundary.forbidden_call": "Role {role} calls forbidden function {call} ({boundary}).",
    "service.external_import": "Role {role} directly imports external implementation {imported}.",
    "contract.external_import": "Role {role} depends on external type {imported}.",
    "adapter.database_import": "Role {role} imports DB module {imported}.",
    "adapter.database_call": "Adapter calls DB function {call}.",
    "layer.entry_import": "Entrypoint imports forbidden {kind} dependency {value}.",
    "layer.entry_call": "Entrypoint directly calls forbidden {kind} operation {value}.",
    "layer.service_import": "Service imports forbidden {kind} dependency {value}.",
    "layer.service_call": "Service directly calls forbidden {kind} operation {value}.",
    "layer.query_import": "Queries imports forbidden {kind} dependency {value}.",
    "layer.query_call": "Queries directly calls forbidden {kind} operation {value}.",
    "layer.model_import": "Model imports forbidden {kind} dependency {value}.",
    "layer.model_call": "Model directly calls forbidden {kind} operation {value}.",
    "wiring.constructor_outside_bootstrap": (
        "Implementation {value} is constructed outside bootstrap wiring."
    ),
    "adapter.external_type_leak": "Public Adapter function exposes external type {value}.",
    "config.settings_construction": (
        "Settings {value} is constructed outside the configuration boundary."
    ),
    "dependency.outside_entry": (
        "Request dependency injection {value} is used outside an entrypoint."
    ),
    "test.nested_conftest": "{value} is outside the configured test root.",
    "test.raw_http_client": "Test directly uses {value} instead of an approved test client.",
    "http.timeout_missing": "External HTTP client {call} has no explicit timeout.",
    "log.external_call_unwrapped": "External call {call} is outside a registered logging context.",
    "import.dynamic_import": "Dynamic import {call} is called in production code.",
    "runtime.asyncio_run": "{call} is called inside an async function.",
    "runtime.hidden_dispatch": "Unapproved execution shortcut {call} is called.",
    "transaction.external_call_while_open": (
        "External call {call} is awaited while a DB session or transaction is open."
    ),
    "transaction.multi_write_unprotected": (
        "Multiple DB writes execute without a transaction boundary."
    ),
    "async.blocking_call": "Blocking call {call} is used inside an async function.",
    "security.direct_access": "Role {role} directly uses security-sensitive function {call}.",
    "catalog.unknown_risky_call": "External call has no registered risk classification: {call}",
    "dto.not_frozen": "Internal DTO {symbol} is not a frozen dataclass or Pydantic model.",
    "dto.mutable_field": "Internal DTO {symbol} exposes a mutable field type.",
    "dto.name_suffix": "Internal DTO {symbol} has no role suffix in its name.",
    "snapshot.wrong_role": "Stored Snapshot {symbol} is outside the snapshots role.",
    "snapshot.version_missing": "Stored Snapshot {symbol} has no version in its name.",
    "schema.invalid_config": "HTTP Schema {symbol} has invalid required configuration.",
    "schema.field_inheritance": "HTTP Schema {symbol} inherits business fields.",
    "schema.from_internal_missing": "Response Schema {symbol} has no from_internal method.",
    "schema.mapper_missing": "Response Schema {symbol} has no configured mapper method.",
    "schema.mapper_not_classmethod": "Mapper for response Schema {symbol} must be a classmethod.",
    "schema.mapper_input_untyped": (
        "Mapper for response Schema {symbol} has no input type annotation."
    ),
    "schema.mapper_return_untyped": (
        "Mapper for response Schema {symbol} has no return type annotation."
    ),
    "schema.bulk_mapping": "Response Schema {symbol} uses automatic or bulk copying.",
    "schema.router_direct_mapping": (
        "Router {symbol} directly constructs response Schema {missing}."
    ),
    "api.endpoint_docstring_missing": "Endpoint {symbol} has no docstring.",
    "api.responses_missing": "Endpoint {symbol} has no responses declaration.",
    "api.response_model_missing": "Endpoint {symbol} has no response_model declaration.",
    "api.field_metadata_missing": "Public API field {symbol} is missing {missing}.",
    "api.router_tags_missing": "APIRouter {symbol} and its registration have no tags.",
    "api.query_description_missing": "Query parameter {symbol} has no description.",
    "api.parameter_description_missing": "Parameter {symbol} has no description.",
    "enum.class_suffix": "Enum class {kind} has an Enum suffix.",
    "enum.base_type": "Enum {kind} does not use StrEnum.",
    "enum.shared_location": "Shared Enum is outside the central directory ({kind}).",
    "enum.private_import": "Private Enum {kind} is imported from another module.",
    "enum.member_name": "Invalid Enum member name format ({kind}).",
    "enum.member_value": "Invalid Enum value format ({kind}).",
    "orm.relationship_loading": "Invalid relationship loading configuration ({kind}).",
    "orm.enum_contract": "DB Enum configuration is missing or invalid ({kind}).",
    "database.timezone_missing": "Timestamp DB column is missing {kind} configuration.",
    "database.raw_sql": "Raw SQL function {kind} is used directly.",
    "exception.code_missing": "Business exception {symbol} has no error code.",
    "exception.code_unregistered": (
        "Error code for business exception {symbol} is not in the registry."
    ),
    "exception.code_duplicate": "Error code {kind} is used by multiple business exceptions.",
    "exception.name_duplicate": "Business exception name {kind} occurs in multiple modules.",
    "exception.code_unused": "Error code {kind} is neither used nor reserved.",
    "exception.family_unregistered": (
        "Exception {symbol} is outside the registered business exception hierarchy."
    ),
}


@dataclass(frozen=True)
class FindingProcessingResult:
    diagnostics: tuple[Diagnostic, ...]
    engine_issues: tuple[EngineIssue, ...]
    ignore_audit: IgnoreAudit
    approval_audit: ApprovalAudit


class FindingProcessor:
    def process(
        self,
        *,
        findings: tuple[Finding, ...],
        policy: EffectivePolicy,
        help_by_rule: FrozenMap[RuleId, str],
        ignores: tuple[InlineIgnore, ...],
        classifications: ClassificationIndex | None = None,
        canonicalize: Callable[[SymbolId], SymbolId] | None = None,
        preused_approval_keys: tuple[str, ...] = (),
    ) -> FindingProcessingResult:
        directives = {(item.path, item.line, item.rule_id): item for item in ignores}
        used_ignores: set[str] = set()
        used_approvals = set(preused_approval_keys)
        diagnostics: list[Diagnostic] = []
        for finding in findings:
            key = (
                finding.primary_location.path,
                finding.primary_location.start_line,
                finding.rule_id,
            )
            directive = directives.get(key)
            disposition = FindingDisposition.ACTIVE
            approval = _matching_approval(finding, policy, classifications, canonicalize)
            approved = False
            if directive is not None:
                disposition = FindingDisposition.IGNORED
                used_ignores.add(directive.key)
            elif approval is not None:
                disposition = FindingDisposition.IGNORED
                used_approvals.add(approval.key)
                approved = True
            evidence = finding.evidence
            if approval is not None and approved:
                evidence = (
                    *evidence,
                    EvidenceItem("approval_reason", approval.reason),
                    EvidenceItem("approval_key", approval.key),
                )
            setting = policy.setting(finding.rule_id)
            diagnostics.append(
                Diagnostic(
                    rule_id=finding.rule_id,
                    level=setting.level,
                    message=_render_message(finding),
                    primary_location=finding.primary_location,
                    related_locations=finding.related_locations,
                    evidence=evidence,
                    help=help_by_rule.get(finding.rule_id),
                    fingerprint=finding.fingerprint,
                    disposition=disposition,
                    source=finding.source,
                )
            )

        unused = tuple(item for item in ignores if item.key not in used_ignores)
        for directive in unused:
            diagnostics.append(_unused_ignore_diagnostic(directive, help_by_rule))

        ordered = tuple(
            sorted(
                diagnostics,
                key=lambda item: (
                    item.primary_location.path.value,
                    item.primary_location.start_line,
                    item.primary_location.start_column,
                    item.rule_id.value,
                    item.fingerprint.value,
                ),
            )
        )
        return FindingProcessingResult(
            diagnostics=ordered,
            engine_issues=(),
            ignore_audit=IgnoreAudit(
                used=tuple(sorted(used_ignores)),
                unused=tuple(sorted(item.key for item in unused)),
            ),
            approval_audit=ApprovalAudit(
                used=tuple(sorted(used_approvals)),
                unused=tuple(
                    approval.key
                    for approval in policy.approvals
                    if approval.key not in used_approvals
                ),
            ),
        )


def _matching_approval(
    finding: Finding,
    policy: EffectivePolicy,
    classifications: ClassificationIndex | None,
    canonicalize: Callable[[SymbolId], SymbolId] | None,
) -> PolicyApproval | None:
    if classifications is None:
        return None
    zone = classifications.get(finding.module_id).zone
    symbol = finding.enclosing_symbol or SymbolId(finding.module_id.value)
    canonical = canonicalize(symbol) if canonicalize is not None else symbol
    tokens = {str(value) for _, value in finding.arguments.items() if value is not None}
    for item in finding.evidence:
        if isinstance(item.value, tuple):
            tokens.update(item.value)
        elif item.value is not None:
            tokens.add(str(item.value))
    return next(
        (
            approval
            for approval in policy.approvals
            if approval.kind in _SUPPRESSION_APPROVAL_KINDS
            and approval.rule_id == finding.rule_id
            and (canonicalize(approval.symbol) if canonicalize is not None else approval.symbol)
            == canonical
            and zone in approval.zones
            and (approval.target is None or approval.target in tokens)
        ),
        None,
    )


def _unused_ignore_diagnostic(
    directive: InlineIgnore,
    help_by_rule: FrozenMap[RuleId, str],
) -> Diagnostic:
    digest = hashlib.sha256(directive.key.encode()).hexdigest()
    return Diagnostic(
        rule_id=_IGNORE_RULE_ID,
        level=RuleLevel.ENFORCED,
        message=f"Unused ignore comment: {directive.rule_id.value}",
        primary_location=directive.location,
        related_locations=(),
        evidence=(EvidenceItem("ignored_rule", directive.rule_id.value),),
        help=help_by_rule.get(_IGNORE_RULE_ID),
        fingerprint=FindingFingerprint(digest),
        disposition=FindingDisposition.ACTIVE,
        source=FindingSource.STATIC,
    )


def _render_message(finding: Finding) -> str:
    template = _MESSAGES.get(finding.message_key)
    if template is None:
        return finding.message_key
    return template.format(**dict(finding.arguments.items()))
