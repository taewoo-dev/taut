from __future__ import annotations

import re

from taut.domain.evaluations import ChangeImpact, RuleTarget, RuleTargetRef, RuleVerdict
from taut.domain.facts import AnalysisStage, ClassFact, FieldFact
from taut.domain.findings import EvidenceItem, Finding
from taut.domain.ids import FactId, ModuleId, RuleId, SymbolId
from taut.domain.location import SourceRange
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import build_finding, rule_uncertainty

RULE_ID = RuleId("ENUM001")
RULE_VERSION = 4
_UPPER_NAME = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$")
_LOWER_VALUE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
_ENUM_BASES = frozenset(
    {
        "builtins.Enum",
        "builtins.IntEnum",
        "builtins.StrEnum",
        "enum.Enum",
        "enum.IntEnum",
        "enum.StrEnum",
    }
)
_STR_ENUM_BASES = frozenset({"builtins.StrEnum", "enum.StrEnum"})


def _finding(
    module_id: ModuleId,
    enclosing_symbol: SymbolId | None,
    subject: FactId,
    location: SourceRange,
    message_key: str,
    kind: str,
) -> Finding:
    return build_finding(
        rule_id=RULE_ID,
        rule_version=RULE_VERSION,
        module_id=module_id,
        enclosing_symbol=enclosing_symbol,
        subject=subject,
        normalized_subject=f"{kind}:{subject.value}",
        message_key=message_key,
        arguments=(("kind", kind),),
        location=location,
        evidence=(EvidenceItem("kind", kind),),
    )


def _is_enum(class_fact: ClassFact) -> bool:
    return any(symbol.value in _ENUM_BASES for base in class_fact.bases for symbol in base.symbols)


def _is_str_enum(class_fact: ClassFact) -> bool:
    return any(
        symbol.value in _STR_ENUM_BASES for base in class_fact.bases for symbol in base.symbols
    )


def _inside_shared_enum_module(module_id: ModuleId, prefixes: tuple[ModuleId, ...]) -> bool:
    return any(
        module_id == prefix or module_id.value.startswith(f"{prefix.value}.") for prefix in prefixes
    )


class EnumShapeRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("ENUM001 requires a module target")
        uncertainty = rule_uncertainty(RULE_ID, target, context, target.module_id)
        if uncertainty is not None:
            return uncertainty
        module = context.model.module(target.module_id)
        findings: list[Finding] = []
        for class_fact in module.classes:
            if not _is_enum(class_fact):
                continue
            if (
                not _is_str_enum(class_fact)
                and class_fact.symbol_id not in context.policy.code.non_str_enum_exceptions
            ):
                findings.append(
                    _finding(
                        target.module_id,
                        class_fact.symbol_id,
                        class_fact.id,
                        class_fact.location,
                        "enum.base_type",
                        class_fact.name,
                    )
                )
            if class_fact.name.endswith("Enum"):
                findings.append(
                    _finding(
                        target.module_id,
                        class_fact.symbol_id,
                        class_fact.id,
                        class_fact.location,
                        "enum.class_suffix",
                        "Enum suffix",
                    )
                )
            if not class_fact.name.startswith("_") and not _inside_shared_enum_module(
                target.module_id, context.policy.code.shared_enum_modules
            ):
                findings.append(
                    _finding(
                        target.module_id,
                        class_fact.symbol_id,
                        class_fact.id,
                        class_fact.location,
                        "enum.shared_location",
                        "public enum location",
                    )
                )
            findings.extend(self._member_findings(class_fact, module.fields, target, context))
        findings.extend(self._private_import_findings(target, context))
        if findings:
            return RuleEvaluation(RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(RULE_ID, target, RuleVerdict.PASS, ())

    def _private_import_findings(
        self,
        target: RuleTargetRef,
        context: PolicyContext,
    ) -> list[Finding]:
        if target.module_id is None:
            return []
        findings: list[Finding] = []
        for import_fact in context.model.module(target.module_id).imports:
            if not import_fact.is_from:
                continue
            imported_name = import_fact.imported_name
            class_name = imported_name.rsplit(".", maxsplit=1)[-1]
            if not class_name.startswith("_"):
                continue
            origin_id = ModuleId(import_fact.imported_module_name)
            if origin_id == target.module_id:
                continue
            try:
                origin = context.model.module(origin_id)
            except KeyError:
                continue
            imported_symbol = SymbolId(imported_name)
            if not any(
                item.symbol_id == imported_symbol and _is_enum(item) for item in origin.classes
            ):
                continue
            findings.append(
                _finding(
                    target.module_id,
                    imported_symbol,
                    import_fact.id,
                    import_fact.location,
                    "enum.private_import",
                    imported_name,
                )
            )
        return findings

    def _member_findings(
        self,
        class_fact: ClassFact,
        fields: tuple[FieldFact, ...],
        target: RuleTargetRef,
        context: PolicyContext,
    ) -> list[Finding]:
        if target.module_id is None:
            return []
        findings: list[Finding] = []
        for field in fields:
            if field.owner_symbol != class_fact.symbol_id or field.name.startswith("_"):
                continue
            if _UPPER_NAME.fullmatch(field.name) is None:
                findings.append(
                    _finding(
                        target.module_id,
                        class_fact.symbol_id,
                        field.id,
                        field.location,
                        "enum.member_name",
                        field.name,
                    )
                )
            if (
                field.value is not None
                and field.value.literal_kind == "str"
                and class_fact.symbol_id not in context.policy.code.uppercase_enum_exceptions
            ):
                value = (field.value.literal_value or "").strip("'\"")
                if _LOWER_VALUE.fullmatch(value) is None:
                    findings.append(
                        _finding(
                            target.module_id,
                            class_fact.symbol_id,
                            field.id,
                            field.location,
                            "enum.member_value",
                            value,
                        )
                    )
        return findings


def enum_rule_definition() -> RuleDefinition:
    return RuleDefinition(
        RULE_ID,
        RULE_VERSION,
        "Enum 공개 계약",
        "Enum 위치, 공개 범위, 자료형, 이름과 값 형식을 맞추세요.",
        RuleTarget.MODULE,
        RuleRequirements(frozenset(), AnalysisStage.FACTS_READY, False, False),
        ChangeImpact.SELF,
        EnumShapeRule(),
        ("tests/fixtures/rules/enum/compliant.py",),
        ("tests/fixtures/rules/enum/violation.py",),
    )
