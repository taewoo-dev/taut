from __future__ import annotations

from taut.configuration.catalog import Effect, EffectResolutionState
from taut.domain.evaluations import (
    ChangeImpact,
    EvaluationReason,
    RuleTarget,
    RuleTargetRef,
    RuleVerdict,
)
from taut.domain.facts import AnalysisStage, CallFact, FunctionFact, ResolutionState
from taut.domain.findings import EvidenceItem, Finding
from taut.domain.ids import RuleId, SymbolId
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import (
    build_finding,
    target_uncertainty,
    unresolved_effect_evaluation,
)

RULE_ID = RuleId("TX001")
ATOMICITY_RULE_ID = RuleId("TX003")
RULE_VERSION = 3
TRANSACTION_EFFECTS = frozenset({Effect.TX_COMMIT, Effect.TX_ROLLBACK})


class TransactionOwnerRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.fact_id is None or target.module_id is None:
            raise ValueError("TX001 requires a call target")
        incomplete = target_uncertainty(RULE_ID, target, context)
        if incomplete is not None:
            return incomplete
        call = context.model.call(target.fact_id)
        uncertain = unresolved_effect_evaluation(
            RULE_ID, target, context, call.id, TRANSACTION_EFFECTS
        )
        if uncertain is not None:
            return uncertain
        resolution = context.effect_of(call)
        if resolution.state is EffectResolutionState.SYMBOL_UNRESOLVED:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        if resolution.state is not EffectResolutionState.MATCHED:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        matched = TRANSACTION_EFFECTS.intersection(resolution.effects)
        if not matched:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        classification = context.classification.get(target.module_id)
        if classification.role is None:
            return RuleEvaluation(
                RULE_ID,
                target,
                RuleVerdict.INDETERMINATE,
                (),
                EvaluationReason("missing_role", "파일의 role이 정해지지 않았습니다."),
            )
        if classification.role in context.policy.transaction_owner_roles:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.PASS, ())
        effect = sorted(item.value for item in matched)[0]
        finding = build_finding(
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            module_id=call.module_id,
            enclosing_symbol=call.enclosing_symbol,
            subject=call.id,
            normalized_subject=f"{effect}:{classification.role.value}:{call.id.value}",
            message_key="transaction.outside_owner",
            arguments=(("effect", effect), ("role", classification.role.value)),
            location=call.location,
            evidence=(
                EvidenceItem("effect", effect),
                EvidenceItem("role", classification.role.value),
            ),
        )
        return RuleEvaluation(RULE_ID, target, RuleVerdict.FAIL, (finding,))


def transaction_rule_definition() -> RuleDefinition:
    return RuleDefinition(
        id=RULE_ID,
        behavior_version=RULE_VERSION,
        title="transaction 종료 위치 제한",
        help="commit과 rollback은 저장소에서 정한 transaction owner에서만 실행하세요.",
        target=RuleTarget.CALL,
        requirements=RuleRequirements(frozenset(), AnalysisStage.RESOLVED, False, False),
        change_impact=ChangeImpact.SELF,
        implementation=TransactionOwnerRule(),
        compliant_fixtures=("tests/fixtures/rules/transaction/compliant.py",),
        violation_fixtures=("tests/fixtures/rules/transaction/violation.py",),
    )


_WRITE_METHODS = frozenset(
    {
        "add",
        "add_all",
        "bulk_create",
        "bulk_update",
        "create",
        "delete",
        "flush",
        "get_or_create",
        "merge",
        "save",
        "update",
        "update_or_create",
    }
)
_BUILTIN_BOUNDARIES = frozenset(
    {
        SymbolId("tortoise.transactions.atomic"),
        SymbolId("tortoise.transactions.in_transaction"),
    }
)


def _decorated_boundary(function: FunctionFact, context: PolicyContext) -> bool:
    allowed = context.policy.transaction_boundary_decorators.union(_BUILTIN_BOUNDARIES)
    module = context.model.module(function.module_id)
    return any(
        item.decorated_symbol == function.symbol_id and context.symbol_in(item.ref.symbol, allowed)
        for item in module.decorators
    )


def _lexical_boundary(call: CallFact, context: PolicyContext) -> bool:
    allowed = context.policy.transaction_boundary_contexts.union(_BUILTIN_BOUNDARIES)
    return any(context.symbol_in(item.symbol, allowed) for item in call.enclosing_contexts)


def _database_write_range(call: CallFact, context: PolicyContext) -> tuple[int, int]:
    tortoise = context.tortoise_queries.get(call.id)
    if tortoise is not None and tortoise.is_write:
        return (1, 1) if tortoise.confidence is ResolutionState.RESOLVED else (0, 1)
    symbol = call.ref.symbol
    if call.ref.state is ResolutionState.RESOLVED and symbol is not None:
        canonical = context.model.canonical_symbol(symbol).value
        method = canonical.rsplit(".", maxsplit=1)[-1]
        if method in _WRITE_METHODS and canonical.startswith("sqlalchemy."):
            return 1, 1
    method = call.ref.written_name.rsplit(".", maxsplit=1)[-1]
    if method not in _WRITE_METHODS:
        return 0, 0
    root = call.ref.written_name.split(".", maxsplit=1)[0].split("(", maxsplit=1)[0]
    module = context.model.module(call.module_id)
    grounded = any(
        class_fact.name == root
        and any(
            base_symbol.value == "tortoise.models.Model"
            for base in class_fact.bases
            for base_symbol in base.symbols
        )
        for class_fact in module.classes
    )
    return (1, 1) if grounded else (0, 0)


class MultiWriteAtomicityRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.kind is not RuleTarget.PROJECT:
            raise ValueError("TX003 requires a project target")
        functions = {
            function.symbol_id: function
            for module_id in context.model.modules()
            for function in context.model.module(module_id).functions
        }
        calls = {
            symbol: tuple(
                call
                for call in context.model.module(function.module_id).calls
                if call.enclosing_symbol == symbol
            )
            for symbol, function in functions.items()
        }
        summaries = {symbol: (0, 0) for symbol in functions}
        for _ in range(len(functions) + 1):
            changed = False
            for symbol, function in functions.items():
                lower = 0
                upper = 0
                if not _decorated_boundary(function, context):
                    for call in calls[symbol]:
                        if _lexical_boundary(call, context):
                            continue
                        direct_lower, direct_upper = _database_write_range(call, context)
                        if (
                            call.ref.state is ResolutionState.RESOLVED
                            and call.ref.symbol in summaries
                        ):
                            helper_lower, helper_upper = summaries[call.ref.symbol]
                            direct_lower += helper_lower
                            direct_upper += helper_upper
                        else:
                            candidate_ranges = tuple(
                                summaries[item] for item in call.ref.candidates if item in summaries
                            )
                            if candidate_ranges:
                                direct_upper += max(item[1] for item in candidate_ranges)
                        lower = min(lower + direct_lower, 2)
                        upper = min(upper + direct_upper, 2)
                summary = lower, upper
                if summaries[symbol] != summary:
                    summaries[symbol] = summary
                    changed = True
            if not changed:
                break

        findings: list[Finding] = []
        uncertain = False
        for symbol, (lower, upper) in summaries.items():
            function = functions[symbol]
            role = context.classification.get(function.module_id).role
            if role not in context.policy.code.service_roles or upper < 2:
                continue
            if lower < 2:
                uncertain = True
                continue
            findings.append(
                build_finding(
                    rule_id=ATOMICITY_RULE_ID,
                    rule_version=1,
                    module_id=function.module_id,
                    enclosing_symbol=symbol,
                    subject=function.id,
                    normalized_subject=f"multi-write:{symbol.value}",
                    message_key="transaction.multi_write_unprotected",
                    arguments=(("writes", str(lower)),),
                    location=function.location,
                    evidence=(EvidenceItem("writes", str(lower)),),
                )
            )
        if findings:
            return RuleEvaluation(ATOMICITY_RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        if uncertain:
            return RuleEvaluation(
                ATOMICITY_RULE_ID,
                target,
                RuleVerdict.INDETERMINATE,
                (),
                EvaluationReason(
                    "uncertain_transaction_write",
                    "서비스 실행 경로의 DB 쓰기 수를 확정하지 못했습니다.",
                ),
            )
        return RuleEvaluation(ATOMICITY_RULE_ID, target, RuleVerdict.PASS, ())


def multi_write_atomicity_rule_definition() -> RuleDefinition:
    return RuleDefinition(
        id=ATOMICITY_RULE_ID,
        behavior_version=1,
        title="다중 쓰기 원자성",
        help="한 서비스 실행 경로의 여러 DB 쓰기는 증명 가능한 transaction 경계로 묶으세요.",
        target=RuleTarget.PROJECT,
        requirements=RuleRequirements(frozenset(), AnalysisStage.RESOLVED, False, True),
        change_impact=ChangeImpact.PROJECT,
        implementation=MultiWriteAtomicityRule(),
        compliant_fixtures=("tests/fixtures/rules/transaction_atomicity/compliant.py",),
        violation_fixtures=("tests/fixtures/rules/transaction_atomicity/violation.py",),
    )
