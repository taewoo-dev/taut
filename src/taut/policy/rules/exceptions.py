from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence

from taut.configuration.manifest import Zone
from taut.domain.evaluations import (
    ChangeImpact,
    EvaluationReason,
    RuleTarget,
    RuleTargetRef,
    RuleVerdict,
)
from taut.domain.facts import (
    AnalysisStage,
    CallFact,
    ClassFact,
    ExpressionSummary,
    FieldFact,
    ResolutionState,
)
from taut.domain.findings import EvidenceItem, Finding
from taut.domain.ids import FactId, ModuleId, RuleId, SymbolId
from taut.domain.location import SourceRange
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import build_finding, project_fact_uncertainty

RULE_ID = RuleId("EXC001")
RULE_VERSION = 3


def _finding(
    module_id: ModuleId,
    symbol: SymbolId,
    subject: FactId,
    location: SourceRange,
    message_key: str,
    kind: str,
) -> Finding:
    return build_finding(
        rule_id=RULE_ID,
        rule_version=RULE_VERSION,
        module_id=module_id,
        enclosing_symbol=symbol,
        subject=subject,
        normalized_subject=f"{kind}:{subject.value}",
        message_key=message_key,
        arguments=(("symbol", symbol.value), ("kind", kind)),
        location=location,
        evidence=(EvidenceItem("symbol", symbol.value), EvidenceItem("kind", kind)),
    )


def _base_symbols(class_fact: ClassFact) -> frozenset[SymbolId]:
    return frozenset(symbol for base in class_fact.bases for symbol in base.symbols)


def _is_domain_exception(
    symbol: SymbolId,
    classes: dict[SymbolId, ClassFact],
    base_symbols: frozenset[SymbolId],
    context: PolicyContext,
    visiting: frozenset[SymbolId] = frozenset(),
) -> bool:
    symbol = context.model.canonical_symbol(symbol)
    if context.symbol_in(symbol, base_symbols):
        return True
    if symbol in visiting:
        return False
    class_fact = classes.get(symbol)
    if class_fact is None:
        return False
    return any(
        _is_domain_exception(base, classes, base_symbols, context, visiting | {symbol})
        for base in _base_symbols(class_fact)
    )


def _code_symbol(
    value: ExpressionSummary | None,
    error_enums: frozenset[SymbolId],
    context: PolicyContext,
) -> SymbolId | None:
    if value is None:
        return None
    candidates = tuple(
        symbol
        for symbol in value.symbols
        if context.matching_symbol(symbol, error_enums) is not None
    )
    selected = max(candidates, key=lambda symbol: len(symbol.value), default=None)
    return context.model.canonical_symbol(selected) if selected is not None else None


def _constructor_error_code(
    class_fact: ClassFact,
    calls_by_enclosing: Mapping[SymbolId, Sequence[CallFact]],
) -> tuple[CallFact, ExpressionSummary] | None:
    constructor = SymbolId(f"{class_fact.symbol_id.value}.__init__")
    candidates: list[tuple[CallFact, ExpressionSummary]] = []
    for call in calls_by_enclosing.get(constructor, ()):
        error_code = next(
            (argument.value for argument in call.arguments if argument.name == "error_code"),
            None,
        )
        if error_code is not None:
            candidates.append((call, error_code))
    return candidates[0] if candidates else None


class ExceptionRegistryRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.kind is not RuleTarget.PROJECT:
            raise ValueError("EXC001 requires a project target")
        uncertainty = project_fact_uncertainty(RULE_ID, target, context)
        if uncertainty is not None:
            return uncertainty
        classes: dict[SymbolId, ClassFact] = {}
        fields: list[FieldFact] = []
        calls_by_enclosing: dict[SymbolId, list[CallFact]] = defaultdict(list)
        referenced_codes: set[SymbolId] = set()
        for module_id in context.model.modules():
            if context.classification.get(module_id).zone != Zone("prod"):
                continue
            module = context.model.module(module_id)
            classes.update(
                (context.model.canonical_symbol(class_fact.symbol_id), class_fact)
                for class_fact in module.classes
            )
            fields.extend(module.fields)
            for call in module.calls:
                if call.enclosing_symbol is not None:
                    calls_by_enclosing[call.enclosing_symbol].append(call)
            for reference in module.references:
                symbol = reference.ref.symbol
                if symbol is not None and context.matching_symbol(
                    symbol, context.policy.code.error_code_enum_symbols
                ):
                    referenced_codes.add(context.model.canonical_symbol(symbol))
        policy = context.policy.code
        uncertain_calls = tuple(
            call
            for module_id in context.model.modules()
            if context.classification.get(module_id).zone == Zone("prod")
            for call in context.model.module(module_id).calls
            if call.ref.state is not ResolutionState.RESOLVED
        )
        domains = tuple(
            class_fact
            for symbol, class_fact in classes.items()
            if not context.symbol_in(symbol, policy.abstract_exception_symbols)
            and _is_domain_exception(symbol, classes, policy.exception_base_symbols, context)
        )
        exception_constructors = tuple(
            SymbolId(f"{class_fact.symbol_id.value}.__init__") for class_fact in domains
        )
        if any(
            call.enclosing_symbol in exception_constructors
            and any(argument.name == "error_code" for argument in call.arguments)
            and set(call.ref.candidates).intersection(exception_constructors)
            for call in uncertain_calls
        ):
            return RuleEvaluation(
                RULE_ID,
                target,
                RuleVerdict.INDETERMINATE,
                (),
                EvaluationReason(
                    "uncertain_symbol", "규칙에 필요한 exception constructor를 확정하지 못했습니다."
                ),
            )
        direct_fields = {(field.owner_symbol, field.name): field for field in fields}
        findings: list[Finding] = []
        code_owners: dict[SymbolId, list[tuple[ClassFact, FieldFact | CallFact]]] = defaultdict(
            list
        )
        name_owners: dict[str, list[ClassFact]] = defaultdict(list)
        for class_fact in domains:
            name_owners[class_fact.name].append(class_fact)
            code_field = direct_fields.get((class_fact.symbol_id, "code"))
            constructor_code = _constructor_error_code(class_fact, calls_by_enclosing)
            if code_field is None and constructor_code is None:
                findings.append(
                    _finding(
                        class_fact.module_id,
                        class_fact.symbol_id,
                        class_fact.id,
                        class_fact.location,
                        "exception.code_missing",
                        "code or error_code",
                    )
                )
                continue
            source: FieldFact | CallFact
            value: ExpressionSummary | None
            if code_field is not None:
                source = code_field
                value = code_field.value
            else:
                assert constructor_code is not None
                source, value = constructor_code
            code = _code_symbol(value, policy.error_code_enum_symbols, context)
            if code is None:
                findings.append(
                    _finding(
                        class_fact.module_id,
                        class_fact.symbol_id,
                        source.id,
                        source.location,
                        "exception.code_unregistered",
                        value.written if value else "missing",
                    )
                )
                continue
            code_owners[code].append((class_fact, source))
        for code, code_entries in code_owners.items():
            if len(code_entries) < 2:
                continue
            for class_fact, field in code_entries:
                findings.append(
                    _finding(
                        class_fact.module_id,
                        class_fact.symbol_id,
                        field.id,
                        field.location,
                        "exception.code_duplicate",
                        code.value,
                    )
                )
        for name, name_entries in name_owners.items():
            if len(name_entries) < 2:
                continue
            for class_fact in name_entries:
                findings.append(
                    _finding(
                        class_fact.module_id,
                        class_fact.symbol_id,
                        class_fact.id,
                        class_fact.location,
                        "exception.name_duplicate",
                        name,
                    )
                )
        used_codes = (
            set(code_owners)
            .union(
                context.model.canonical_symbol(symbol)
                for symbol in policy.reserved_error_code_symbols
            )
            .union(referenced_codes)
        )
        for enum_symbol in policy.error_code_enum_symbols:
            canonical_enum = context.model.canonical_symbol(enum_symbol)
            for field in fields:
                if (
                    field.owner_symbol is None
                    or context.model.canonical_symbol(field.owner_symbol) != canonical_enum
                    or field.name.startswith("_")
                ):
                    continue
                canonical_field = context.model.canonical_symbol(field.symbol_id)
                if canonical_field not in used_codes:
                    findings.append(
                        _finding(
                            field.module_id,
                            canonical_enum,
                            field.id,
                            field.location,
                            "exception.code_unused",
                            field.symbol_id.value,
                        )
                    )
        if findings:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(RULE_ID, target, RuleVerdict.PASS, ())


def exception_rule_definition() -> RuleDefinition:
    return RuleDefinition(
        RULE_ID,
        RULE_VERSION,
        "업무 예외와 오류 코드 등록표",
        "업무 예외마다 고유한 등록 오류 코드를 두고 쓰지 않는 코드는 예약 목록에 적으세요.",
        RuleTarget.PROJECT,
        RuleRequirements(frozenset(), AnalysisStage.FACTS_READY, False, True),
        ChangeImpact.PROJECT,
        ExceptionRegistryRule(),
        ("tests/fixtures/rules/exception/compliant.py",),
        ("tests/fixtures/rules/exception/violation.py",),
    )
