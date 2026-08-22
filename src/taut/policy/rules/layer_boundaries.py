from __future__ import annotations

from dataclasses import dataclass

from taut.configuration.catalog import Effect, EffectResolutionState
from taut.configuration.manifest import Role, Zone
from taut.domain.evaluations import ChangeImpact, RuleTarget, RuleTargetRef, RuleVerdict
from taut.domain.facts import (
    AnalysisStage,
    CallFact,
    GuardKind,
    ImportFact,
    ResolutionState,
)
from taut.domain.findings import EvidenceItem, Finding, FindingSubject
from taut.domain.ids import FactId, ModuleId, RuleId, SymbolId
from taut.domain.location import SourceRange
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import (
    build_finding,
    module_fact_uncertainty,
    unresolved_call_evaluation,
    unresolved_use_evaluation,
)

ENTRY_RULE_ID = RuleId("ENTRY001")
SERVICE_RULE_ID = RuleId("SERVICE001")
QUERY_RULE_ID = RuleId("QUERY001")
MODEL_RULE_ID = RuleId("MODEL001")
DEPENDENCY_RULE_ID = RuleId("DEPENDS001")
RULE_VERSION = 1
DEPENDENCY_RULE_VERSION = 2

_ALL_ZONES = frozenset({Zone("prod"), Zone("test"), Zone("migration"), Zone("script")})
_ENTRY_TRANSACTION_METHODS = frozenset({"begin", "begin_nested", "commit", "rollback"})
_QUERY_WRITE_METHODS = frozenset(
    {"add", "add_all", "commit", "delete", "flush", "merge", "rollback"}
)
_QUERY_DML_NAMES = frozenset({"delete", "insert", "update"})


def matches_module_prefix(name: str, prefixes: tuple[ModuleId, ...]) -> ModuleId | None:
    return next(
        (
            prefix
            for prefix in prefixes
            if name == prefix.value or name.startswith(f"{prefix.value}.")
        ),
        None,
    )


def _matches_import(import_fact: ImportFact, prefixes: tuple[ModuleId, ...]) -> ModuleId | None:
    return matches_module_prefix(import_fact.imported_module_name, prefixes)


def _matches_symbol(call: CallFact, symbols: tuple[SymbolId, ...]) -> SymbolId | None:
    symbol = call.ref.symbol
    if call.ref.state is not ResolutionState.RESOLVED or symbol is None:
        return None
    return next(
        (
            prefix
            for prefix in symbols
            if symbol == prefix or symbol.value.startswith(f"{prefix.value}.")
        ),
        None,
    )


def _symbol_in_modules(call: CallFact, modules: tuple[ModuleId, ...]) -> ModuleId | None:
    symbol = call.ref.symbol
    if call.ref.state is not ResolutionState.RESOLVED or symbol is None:
        return None
    return matches_module_prefix(symbol.value, modules)


def _database_primitive(call: CallFact, context: PolicyContext) -> str | None:
    statement = _matches_symbol(call, context.policy.boundaries.database_statement_calls)
    if statement is not None:
        return statement.value
    return None


def _external_call(call: CallFact, context: PolicyContext) -> str | None:
    module = _symbol_in_modules(call, context.policy.boundaries.external_modules)
    if module is not None:
        return module.value
    resolution = context.effect_of(call)
    if (
        resolution.state is EffectResolutionState.MATCHED
        and Effect.EXTERNAL_CALL in resolution.effects
    ):
        return call.ref.symbol.value if call.ref.symbol is not None else call.ref.written_name
    return None


def _argument_uses_symbol(call: CallFact, symbols: frozenset[SymbolId]) -> SymbolId | None:
    return next(
        (
            symbol
            for argument in call.arguments
            for symbol in argument.value.symbols
            if symbol in symbols
        ),
        None,
    )


def build_boundary_finding(
    rule_id: RuleId,
    *,
    module_id: ModuleId,
    subject: FindingSubject,
    enclosing_symbol: SymbolId | None,
    location: SourceRange,
    message_key: str,
    kind: str,
    value: str,
    rule_version: int = RULE_VERSION,
) -> Finding:
    return build_finding(
        rule_id=rule_id,
        rule_version=rule_version,
        module_id=module_id,
        enclosing_symbol=enclosing_symbol,
        subject=subject,
        normalized_subject=f"{kind}:{value}:{subject}",
        message_key=message_key,
        arguments=(("kind", kind), ("value", value)),
        location=location,
        evidence=(EvidenceItem("kind", kind), EvidenceItem("value", value)),
    )


def boundary_result(
    rule_id: RuleId,
    target: RuleTargetRef,
    findings: list[Finding],
) -> RuleEvaluation:
    verdict = RuleVerdict.FAIL if findings else RuleVerdict.PASS
    return RuleEvaluation(rule_id, target, verdict, tuple(findings))


@dataclass(frozen=True)
class _RoleBoundaryRule:
    rule_id: RuleId
    roles_attribute: str
    mode: str

    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError(f"{self.rule_id.value} requires a module target")
        role = context.classification.get(target.module_id).role
        roles: frozenset[Role] = getattr(context.policy.boundaries, self.roles_attribute)
        if role is None or role not in roles:
            return RuleEvaluation(self.rule_id, target, RuleVerdict.NOT_APPLICABLE, ())
        uncertainty = module_fact_uncertainty(self.rule_id, target, context, target.module_id)
        if uncertainty is not None:
            return uncertainty
        candidates = tuple(
            value
            for name in (
                "database_statement_calls",
                "transport_exception_calls",
                "dependency_injection_calls",
                "external_client_constructors",
                "raw_sql_calls",
            )
            for value in getattr(context.policy.boundaries, name)
        )
        uncertainty = unresolved_call_evaluation(
            self.rule_id, target, context, target.module_id, candidates
        )
        if uncertainty is not None:
            return uncertainty
        uncertainty = unresolved_use_evaluation(
            self.rule_id, target, context, target.module_id, candidates
        )
        if uncertainty is not None:
            return uncertainty
        module = context.model.module(target.module_id)
        findings: list[Finding] = []
        for import_fact in module.imports:
            if import_fact.context.guard is GuardKind.TYPE_CHECKING_ONLY:
                continue
            violation = self._import_violation(import_fact, context)
            if violation is None:
                continue
            kind, value = violation
            findings.append(
                build_boundary_finding(
                    self.rule_id,
                    module_id=target.module_id,
                    subject=import_fact.id,
                    enclosing_symbol=import_fact.enclosing_symbol,
                    location=import_fact.location,
                    message_key=f"layer.{self.mode}_import",
                    kind=kind,
                    value=value,
                )
            )
        for call in module.calls:
            violation = self._call_violation(call, context)
            if violation is None:
                continue
            kind, value = violation
            findings.append(
                build_boundary_finding(
                    self.rule_id,
                    module_id=target.module_id,
                    subject=call.id,
                    enclosing_symbol=call.enclosing_symbol,
                    location=call.location,
                    message_key=f"layer.{self.mode}_call",
                    kind=kind,
                    value=value,
                )
            )
        return boundary_result(self.rule_id, target, findings)

    def _import_violation(
        self,
        import_fact: ImportFact,
        context: PolicyContext,
    ) -> tuple[str, str] | None:
        boundaries = context.policy.boundaries
        if self.mode == "entry":
            prefix = _matches_import(import_fact, boundaries.database_modules)
            if prefix is not None and not self._entry_kind_allowed(
                "database", import_fact.module_id, context
            ):
                return "database", import_fact.imported_name
            prefix = _matches_import(import_fact, boundaries.external_modules)
            if prefix is not None and not self._entry_kind_allowed(
                "external", import_fact.module_id, context
            ):
                return "external", import_fact.imported_name
        elif self.mode == "service":
            prefix = _matches_import(import_fact, boundaries.transport_modules)
            if prefix is not None:
                return "transport", import_fact.imported_name
            if _is_statement_import(import_fact, boundaries.database_statement_calls):
                return "database", import_fact.imported_name
        elif self.mode == "query":
            for kind, prefixes in (
                ("external", boundaries.external_modules),
                ("transport", boundaries.transport_modules),
            ):
                prefix = _matches_import(import_fact, prefixes)
                if prefix is not None:
                    return kind, import_fact.imported_name
            if _is_dml_import(import_fact):
                return "write", import_fact.imported_name
        elif self.mode == "model":
            for kind, prefixes in (
                ("external", boundaries.external_modules),
                ("transport", boundaries.transport_modules),
            ):
                prefix = _matches_import(import_fact, prefixes)
                if prefix is not None:
                    return kind, import_fact.imported_name
        return None

    def _call_violation(
        self,
        call: CallFact,
        context: PolicyContext,
    ) -> tuple[str, str] | None:
        boundaries = context.policy.boundaries
        if self.mode == "entry":
            primitive = _database_primitive(call, context)
            if primitive is not None and not self._entry_kind_allowed(
                "database", call.module_id, context
            ):
                return "database", primitive
            provider = _argument_uses_symbol(call, context.policy.transaction_session_providers)
            if provider is not None and not self._entry_kind_allowed(
                "session", call.module_id, context
            ):
                return "session", provider.value
            exception = _matches_symbol(call, boundaries.transport_exception_calls)
            if exception is not None and not self._entry_kind_allowed(
                "transport_exception", call.module_id, context
            ):
                return "transport_exception", exception.value
            external = _external_call(call, context)
            if external is not None and not self._entry_kind_allowed(
                "external", call.module_id, context
            ):
                return "external", external
        elif self.mode == "service":
            primitive = _database_primitive(call, context)
            if primitive is not None:
                return "database", primitive
            transport = _symbol_in_modules(call, boundaries.transport_modules)
            if transport is not None:
                return "transport", call.ref.symbol.value if call.ref.symbol else transport.value
        elif self.mode == "query":
            symbol = call.ref.symbol
            if (
                symbol is not None
                and symbol.value.rsplit(".", maxsplit=1)[-1] in _QUERY_DML_NAMES
                and matches_module_prefix(symbol.value, boundaries.database_modules) is not None
            ):
                return "write", symbol.value
            if (
                _matches_symbol(call, tuple(context.policy.transaction_session_providers))
                is not None
            ):
                return "session", call.ref.written_name
            external = _external_call(call, context)
            if external is not None:
                return "external", external
        elif self.mode == "model":
            external = _external_call(call, context)
            if external is not None:
                return "external", external
            transport = _symbol_in_modules(call, boundaries.transport_modules)
            if transport is not None:
                return "transport", call.ref.symbol.value if call.ref.symbol else transport.value
        return None

    def _entry_kind_allowed(self, kind: str, module_id: ModuleId, context: PolicyContext) -> bool:
        if self.mode != "entry":
            return False
        # The caller has already established that the module has this rule's entry role.
        role = context.classification.get(module_id).role
        return role is not None and kind in context.policy.boundaries.entry_allowed_kinds.get(
            role, frozenset()
        )


def _is_statement_import(import_fact: ImportFact, symbols: tuple[SymbolId, ...]) -> bool:
    statement_names = {symbol.value.rsplit(".", maxsplit=1)[-1] for symbol in symbols}
    return (
        matches_module_prefix(import_fact.imported_module_name, (ModuleId("sqlalchemy"),))
        is not None
        and import_fact.imported_name.rsplit(".", maxsplit=1)[-1] in statement_names
    )


def _is_dml_import(import_fact: ImportFact) -> bool:
    return (
        matches_module_prefix(import_fact.imported_module_name, (ModuleId("sqlalchemy"),))
        is not None
        and import_fact.imported_name.rsplit(".", maxsplit=1)[-1] in _QUERY_DML_NAMES
    )


class DependencyInjectionBoundaryRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("DEPENDS001 requires a module target")
        role = context.classification.get(target.module_id).role
        if role is None:
            return RuleEvaluation(DEPENDENCY_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        uncertainty = module_fact_uncertainty(DEPENDENCY_RULE_ID, target, context, target.module_id)
        if uncertainty is not None:
            return uncertainty
        uncertainty = unresolved_call_evaluation(
            DEPENDENCY_RULE_ID,
            target,
            context,
            target.module_id,
            context.policy.boundaries.dependency_injection_calls,
        )
        if uncertainty is not None:
            return uncertainty
        findings: list[Finding] = []
        matched = False
        calls = context.model.calls_in(target.module_id)
        calls_by_id = {call.id: call for call in calls}
        for call in calls:
            dependency = _matches_symbol(
                call,
                context.policy.boundaries.dependency_injection_calls,
            )
            if dependency is None:
                continue
            matched = True
            if role in context.policy.boundaries.entry_roles or _dependency_registration(
                call, calls_by_id, role, context
            ):
                continue
            findings.append(
                build_boundary_finding(
                    DEPENDENCY_RULE_ID,
                    module_id=target.module_id,
                    subject=call.id,
                    enclosing_symbol=call.enclosing_symbol,
                    location=call.location,
                    message_key="dependency.outside_entry",
                    kind="dependency",
                    value=dependency.value,
                    rule_version=DEPENDENCY_RULE_VERSION,
                )
            )
        if findings:
            return RuleEvaluation(
                DEPENDENCY_RULE_ID,
                target,
                RuleVerdict.FAIL,
                tuple(findings),
            )
        verdict = RuleVerdict.PASS if matched else RuleVerdict.NOT_APPLICABLE
        return RuleEvaluation(DEPENDENCY_RULE_ID, target, verdict, ())


def _dependency_registration(
    call: CallFact,
    calls_by_id: dict[FactId, CallFact],
    role: Role,
    context: PolicyContext,
) -> bool:
    if role not in context.policy.boundaries.dependency_registration_roles:
        return False
    if call.context.argument_name != "dependencies" or call.context.parent_fact_id is None:
        return False
    parent = calls_by_id.get(call.context.parent_fact_id)
    return (
        parent is not None
        and parent.ref.symbol is not None
        and parent.ref.symbol.value
        in {
            "fastapi.APIRouter",
            "fastapi.FastAPI",
            "fastapi.applications.FastAPI",
            "fastapi.routing.APIRouter",
        }
    )


def layer_boundary_rule_definitions() -> tuple[RuleDefinition, ...]:
    requirements = RuleRequirements(frozenset(), AnalysisStage.FACTS_READY, False, False)
    definitions = (
        (
            ENTRY_RULE_ID,
            "진입점의 직접 DB·외부 호출 금지",
            "Router·Consumer·Task는 Service만 호출하고 DB, transaction, "
            "외부 client를 직접 사용하지 마세요.",
            _RoleBoundaryRule(ENTRY_RULE_ID, "entry_roles", "entry"),
            "entry_boundary",
        ),
        (
            SERVICE_RULE_ID,
            "Service의 DB primitive·전송 계층 금지",
            "Service는 transaction만 소유하고 SQL은 Model·Queries에, HTTP 표현은 Router에 두세요.",
            _RoleBoundaryRule(SERVICE_RULE_ID, "service_roles", "service"),
            "service_boundary",
        ),
        (
            QUERY_RULE_ID,
            "Queries 읽기 전용 경계",
            "Queries는 session을 열거나 자료를 바꾸거나 외부 시스템을 호출하지 마세요.",
            _RoleBoundaryRule(QUERY_RULE_ID, "query_roles", "query"),
            "query_boundary",
        ),
        (
            MODEL_RULE_ID,
            "Model 외부 연결 금지",
            "Model은 자기 저장 책임만 맡고 외부 API와 HTTP 표현을 사용하지 마세요.",
            _RoleBoundaryRule(MODEL_RULE_ID, "model_roles", "model"),
            "model_boundary",
        ),
    )
    role_definitions = tuple(
        RuleDefinition(
            rule_id,
            RULE_VERSION,
            title,
            help_text,
            RuleTarget.MODULE,
            requirements,
            ChangeImpact.SELF,
            implementation,
            (f"tests/fixtures/rules/{fixture}/compliant.py",),
            (f"tests/fixtures/rules/{fixture}/violation.py",),
            applies_to_zones=_ALL_ZONES,
        )
        for rule_id, title, help_text, implementation, fixture in definitions
    )
    dependency = RuleDefinition(
        DEPENDENCY_RULE_ID,
        DEPENDENCY_RULE_VERSION,
        "Depends 사용 위치",
        "요청 의존성 주입은 Router·Consumer 같은 진입점에서만 사용하세요.",
        RuleTarget.MODULE,
        requirements,
        ChangeImpact.SELF,
        DependencyInjectionBoundaryRule(),
        ("tests/fixtures/rules/dependency/compliant.py",),
        ("tests/fixtures/rules/dependency/violation.py",),
        applies_to_zones=_ALL_ZONES,
    )
    return (*role_definitions, dependency)
