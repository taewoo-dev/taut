from __future__ import annotations

from fnmatch import fnmatchcase

from taut.configuration.manifest import Zone
from taut.domain.evaluations import (
    ChangeImpact,
    RuleTarget,
    RuleTargetRef,
    RuleVerdict,
)
from taut.domain.facts import AnalysisStage, CallFact, ResolutionState
from taut.domain.findings import EvidenceItem, Finding
from taut.domain.ids import RuleId, SymbolId
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import build_finding, module_fact_uncertainty

IMPORT_RULE_ID = RuleId("IMPORT002")
RUNTIME_RULE_ID = RuleId("RUNTIME001")
TRANSACTION_RULE_ID = RuleId("TX002")
RULE_VERSION = 1
_ALL_ZONES = frozenset({Zone("prod"), Zone("test"), Zone("migration"), Zone("script")})


def _resolved(call: CallFact) -> SymbolId | None:
    if call.ref.state is ResolutionState.RESOLVED:
        return call.ref.symbol
    return None


def _finding(rule_id: RuleId, call: CallFact, message_key: str, kind: str) -> Finding:
    symbol = call.ref.symbol.value if call.ref.symbol is not None else ""
    return build_finding(
        rule_id=rule_id,
        rule_version=RULE_VERSION,
        module_id=call.module_id,
        enclosing_symbol=call.enclosing_symbol,
        subject=call.id,
        normalized_subject=f"{kind}:{call.id.value}",
        message_key=message_key,
        arguments=(("call", symbol),),
        location=call.location,
        evidence=(EvidenceItem("call", symbol), EvidenceItem("kind", kind)),
    )


class DynamicImportRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("IMPORT002 requires a module target")
        uncertain = module_fact_uncertainty(IMPORT_RULE_ID, target, context, target.module_id)
        if uncertain is not None:
            return uncertain
        calls = context.model.module(target.module_id).calls
        forbidden = {SymbolId("builtins.__import__"), SymbolId("importlib.import_module")}
        findings = tuple(
            _finding(IMPORT_RULE_ID, call, "import.dynamic_import", "dynamic_import")
            for call in calls
            if _resolved(call) in forbidden
        )
        if findings:
            return RuleEvaluation(IMPORT_RULE_ID, target, RuleVerdict.FAIL, findings)
        return RuleEvaluation(IMPORT_RULE_ID, target, RuleVerdict.PASS, ())


class RuntimeShortcutRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("RUNTIME001 requires a module target")
        uncertain = module_fact_uncertainty(RUNTIME_RULE_ID, target, context, target.module_id)
        if uncertain is not None:
            return uncertain
        module = context.model.module(target.module_id)
        async_functions = {function.symbol_id for function in module.functions if function.is_async}
        findings: list[Finding] = []
        for call in module.calls:
            symbol = _resolved(call)
            candidate = symbol.value if symbol is not None else ""
            if symbol == SymbolId("asyncio.run") and call.enclosing_symbol in async_functions:
                findings.append(
                    _finding(RUNTIME_RULE_ID, call, "runtime.asyncio_run", "asyncio_run")
                )
                continue
            pattern = next(
                (
                    item
                    for item in context.policy.code.forbidden_runtime_calls
                    if fnmatchcase(candidate, item)
                ),
                None,
            )
            if pattern is not None:
                findings.append(_finding(RUNTIME_RULE_ID, call, "runtime.hidden_dispatch", pattern))
        if findings:
            return RuleEvaluation(RUNTIME_RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(RUNTIME_RULE_ID, target, RuleVerdict.PASS, ())


class ExternalCallTransactionRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("TX002 requires a module target")
        uncertain = module_fact_uncertainty(TRANSACTION_RULE_ID, target, context, target.module_id)
        if uncertain is not None:
            return uncertain
        findings: list[Finding] = []
        for call in context.model.module(target.module_id).calls:
            if not context.indexes.is_logged_external_call(call):
                continue
            context_symbols = {
                item.symbol
                for item in call.enclosing_contexts
                if item.state is ResolutionState.RESOLVED and item.symbol is not None
            }
            holds_session = bool(
                context_symbols.intersection(context.policy.transaction_session_providers)
            )
            holds_transaction = any(
                symbol
                in {
                    SymbolId("sqlalchemy.ext.asyncio.AsyncSession.begin"),
                    SymbolId("sqlalchemy.ext.asyncio.AsyncSession.begin_nested"),
                }
                for symbol in context_symbols
            )
            if holds_session or holds_transaction:
                findings.append(
                    _finding(
                        TRANSACTION_RULE_ID,
                        call,
                        "transaction.external_call_while_open",
                        "external_call",
                    )
                )
        if findings:
            return RuleEvaluation(TRANSACTION_RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(TRANSACTION_RULE_ID, target, RuleVerdict.PASS, ())


def runtime_rule_definitions() -> tuple[RuleDefinition, RuleDefinition, RuleDefinition]:
    requirements = RuleRequirements(frozenset(), AnalysisStage.FACTS_READY, False, False)
    return (
        RuleDefinition(
            IMPORT_RULE_ID,
            RULE_VERSION,
            "동적 import 금지",
            "운영 코드에서는 import_module과 __import__로 의존 관계를 숨기지 마세요.",
            RuleTarget.MODULE,
            requirements,
            ChangeImpact.SELF,
            DynamicImportRule(),
            ("tests/fixtures/rules/runtime/import_compliant.py",),
            ("tests/fixtures/rules/runtime/import_violation.py",),
            applies_to_zones=_ALL_ZONES,
        ),
        RuleDefinition(
            RUNTIME_RULE_ID,
            RULE_VERSION,
            "실행 우회 호출 금지",
            "asyncio.run과 설정한 축약 실행 호출 대신 승인된 실행 경로를 사용하세요.",
            RuleTarget.MODULE,
            requirements,
            ChangeImpact.SELF,
            RuntimeShortcutRule(),
            ("tests/fixtures/rules/runtime/call_compliant.py",),
            ("tests/fixtures/rules/runtime/call_violation.py",),
            applies_to_zones=_ALL_ZONES,
        ),
        RuleDefinition(
            TRANSACTION_RULE_ID,
            RULE_VERSION,
            "DB 거래 중 외부 호출 금지",
            "DB session과 transaction을 닫은 뒤 외부 시스템을 호출하세요.",
            RuleTarget.MODULE,
            requirements,
            ChangeImpact.SELF,
            ExternalCallTransactionRule(),
            ("tests/fixtures/rules/runtime/transaction_compliant.py",),
            ("tests/fixtures/rules/runtime/transaction_violation.py",),
        ),
    )
