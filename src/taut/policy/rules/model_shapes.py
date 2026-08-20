from __future__ import annotations

import re

from taut.analysis.framework.pydantic import (
    PYDANTIC_CONFIGS,
    PYDANTIC_FIELDS,
    PYDANTIC_MODELS,
)
from taut.configuration.manifest import Role
from taut.domain.evaluations import ChangeImpact, RuleTarget, RuleTargetRef, RuleVerdict
from taut.domain.facts import (
    AnalysisStage,
    ClassFact,
    DecoratorFact,
    ExpressionSummary,
    FieldFact,
)
from taut.domain.findings import EvidenceItem, Finding
from taut.domain.ids import FactId, ModuleId, RuleId, SymbolId
from taut.domain.location import SourceRange
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import (
    build_finding,
    rule_uncertainty,
)

DTO_RULE_ID = RuleId("DTO001")
DTO_NAME_RULE_ID = RuleId("DTO002")
SNAPSHOT_RULE_ID = RuleId("SNAPSHOT001")
SCHEMA_CONFIG_RULE_ID = RuleId("SCHEMA001")
SCHEMA_INHERITANCE_RULE_ID = RuleId("SCHEMA002")
RULE_VERSION = 1
_VERSIONED_SNAPSHOT = re.compile(r".+SnapshotV[1-9][0-9]*$")
_MUTABLE_ANNOTATION = re.compile(r"(?:^|[\[| ,])(?:list|dict|set|List|Dict|Set)[\[| ,]")
_REQUEST_SUFFIXES = (
    "Create",
    "Filter",
    "Input",
    "Params",
    "Patch",
    "Query",
    "Request",
    "Update",
)


def _role(target: RuleTargetRef, context: PolicyContext) -> Role | None:
    if target.module_id is None:
        return None
    return context.classification.get(target.module_id).role


def _is_base_model(class_fact: ClassFact) -> bool:
    return any(
        any(
            symbol.value in {"pydantic.BaseModel", "pydantic.main.BaseModel"}
            for symbol in base.symbols
        )
        for base in class_fact.bases
    )


def _decorator(
    decorators: tuple[DecoratorFact, ...], class_fact: ClassFact, symbol: SymbolId
) -> DecoratorFact | None:
    return next(
        (
            item
            for item in decorators
            if item.decorated_symbol == class_fact.symbol_id and item.ref.symbol == symbol
        ),
        None,
    )


def _decorator_argument(decorator: DecoratorFact, name: str) -> ExpressionSummary | None:
    return next(
        (argument.value for argument in decorator.arguments if argument.name == name),
        None,
    )


def _finding(
    rule_id: RuleId,
    module_id: ModuleId,
    symbol: SymbolId,
    subject: FactId,
    location: SourceRange,
    message_key: str,
    kind: str,
) -> Finding:
    return build_finding(
        rule_id=rule_id,
        rule_version=RULE_VERSION,
        module_id=module_id,
        enclosing_symbol=symbol,
        subject=subject,
        normalized_subject=f"{kind}:{subject.value}",
        message_key=message_key,
        arguments=(("symbol", symbol.value),),
        location=location,
        evidence=(EvidenceItem("symbol", symbol.value), EvidenceItem("kind", kind)),
    )


class ImmutableDtoRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("DTO001 requires a module target")
        uncertainty = rule_uncertainty(
            DTO_RULE_ID, target, context, target.module_id, (PYDANTIC_MODELS, PYDANTIC_FIELDS)
        )
        if uncertainty is not None:
            return uncertainty
        if _role(target, context) not in context.policy.code.dto_roles:
            return RuleEvaluation(DTO_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        module = context.model.module(target.module_id)
        findings: list[Finding] = []
        for class_fact in module.classes:
            dataclass = _decorator(module.decorators, class_fact, SymbolId("dataclasses.dataclass"))
            if dataclass is None:
                continue
            frozen = _decorator_argument(dataclass, "frozen")
            if frozen is None or frozen.literal_value != "True":
                findings.append(
                    _finding(
                        DTO_RULE_ID,
                        target.module_id,
                        class_fact.symbol_id,
                        dataclass.id,
                        dataclass.location,
                        "dto.not_frozen",
                        "frozen",
                    )
                )
            for field in module.fields:
                if field.owner_symbol != class_fact.symbol_id or field.annotation is None:
                    continue
                mutable_symbols = {
                    "builtins.dict",
                    "builtins.list",
                    "builtins.set",
                    "typing.Dict",
                    "typing.List",
                    "typing.Set",
                }
                is_mutable = any(
                    symbol.value in mutable_symbols for symbol in field.annotation.symbols
                ) or bool(_MUTABLE_ANNOTATION.search(field.annotation.written.strip("'\"")))
                if is_mutable:
                    findings.append(
                        _finding(
                            DTO_RULE_ID,
                            target.module_id,
                            class_fact.symbol_id,
                            field.id,
                            field.location,
                            "dto.mutable_field",
                            field.name,
                        )
                    )
        verdict = RuleVerdict.FAIL if findings else RuleVerdict.PASS
        return RuleEvaluation(DTO_RULE_ID, target, verdict, tuple(findings))


class DtoNameRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("DTO002 requires a module target")
        uncertainty = rule_uncertainty(
            DTO_NAME_RULE_ID, target, context, target.module_id, (PYDANTIC_MODELS,)
        )
        if uncertainty is not None:
            return uncertainty
        if _role(target, context) not in context.policy.code.dto_roles:
            return RuleEvaluation(DTO_NAME_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        module = context.model.module(target.module_id)
        findings = tuple(
            _finding(
                DTO_NAME_RULE_ID,
                target.module_id,
                class_fact.symbol_id,
                class_fact.id,
                class_fact.location,
                "dto.name_suffix",
                class_fact.name,
            )
            for class_fact in module.classes
            if _decorator(module.decorators, class_fact, SymbolId("dataclasses.dataclass"))
            is not None
            and not class_fact.name.endswith(context.policy.code.dto_name_suffixes)
        )
        if findings:
            return RuleEvaluation(DTO_NAME_RULE_ID, target, RuleVerdict.FAIL, findings)
        return RuleEvaluation(DTO_NAME_RULE_ID, target, RuleVerdict.PASS, ())


class SnapshotPlacementRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("SNAPSHOT001 requires a module target")
        uncertainty = rule_uncertainty(SNAPSHOT_RULE_ID, target, context, target.module_id)
        if uncertainty is not None:
            return uncertainty
        role = _role(target, context)
        module = context.model.module(target.module_id)
        snapshot_file = module.module.path.value.endswith("_snapshot.py")
        findings: list[Finding] = []
        for class_fact in module.classes:
            if not _is_base_model(class_fact) or (
                "Snapshot" not in class_fact.name and not snapshot_file
            ):
                continue
            if role not in context.policy.code.snapshot_roles:
                findings.append(
                    _finding(
                        SNAPSHOT_RULE_ID,
                        target.module_id,
                        class_fact.symbol_id,
                        class_fact.id,
                        class_fact.location,
                        "snapshot.wrong_role",
                        "location",
                    )
                )
            elif _VERSIONED_SNAPSHOT.fullmatch(class_fact.name) is None:
                findings.append(
                    _finding(
                        SNAPSHOT_RULE_ID,
                        target.module_id,
                        class_fact.symbol_id,
                        class_fact.id,
                        class_fact.location,
                        "snapshot.version_missing",
                        "version",
                    )
                )
        if findings:
            return RuleEvaluation(SNAPSHOT_RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(SNAPSHOT_RULE_ID, target, RuleVerdict.PASS, ())


def _model_config(fields: tuple[FieldFact, ...], class_fact: ClassFact) -> FieldFact | None:
    return next(
        (
            field
            for field in fields
            if field.owner_symbol == class_fact.symbol_id and field.name == "model_config"
        ),
        None,
    )


class SchemaConfigRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("SCHEMA001 requires a module target")
        uncertainty = rule_uncertainty(
            SCHEMA_CONFIG_RULE_ID, target, context, target.module_id, (PYDANTIC_CONFIGS,)
        )
        if uncertainty is not None:
            return uncertainty
        if _role(target, context) not in context.policy.code.schema_roles:
            return RuleEvaluation(SCHEMA_CONFIG_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        module = context.model.module(target.module_id)
        findings: list[Finding] = []
        for class_fact in module.classes:
            if (
                not _is_base_model(class_fact)
                or class_fact.symbol_id in context.policy.code.generic_schema_bases
            ):
                continue
            field = _model_config(module.fields, class_fact)
            expected = (
                context.policy.code.request_config_symbols
                if class_fact.name.endswith(_REQUEST_SUFFIXES)
                else context.policy.code.response_config_symbols
            )
            actual: set[SymbolId] = set(field.value.symbols) if field and field.value else set()
            inline = any(symbol.value.endswith("ConfigDict") for symbol in actual)
            if field is None or not actual.intersection(expected) or inline:
                subject = field.id if field is not None else class_fact.id
                location = field.location if field is not None else class_fact.location
                findings.append(
                    _finding(
                        SCHEMA_CONFIG_RULE_ID,
                        target.module_id,
                        class_fact.symbol_id,
                        subject,
                        location,
                        "schema.invalid_config",
                        "request" if class_fact.name.endswith(_REQUEST_SUFFIXES) else "response",
                    )
                )
        if findings:
            return RuleEvaluation(SCHEMA_CONFIG_RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(SCHEMA_CONFIG_RULE_ID, target, RuleVerdict.PASS, ())


class SchemaInheritanceRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("SCHEMA002 requires a module target")
        uncertainty = rule_uncertainty(
            SCHEMA_INHERITANCE_RULE_ID, target, context, target.module_id, (PYDANTIC_MODELS,)
        )
        if uncertainty is not None:
            return uncertainty
        if _role(target, context) not in context.policy.code.schema_roles:
            return RuleEvaluation(
                SCHEMA_INHERITANCE_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ()
            )
        findings: list[Finding] = []
        for class_fact in context.model.module(target.module_id).classes:
            if class_fact.symbol_id in context.policy.code.generic_schema_bases:
                continue
            forbidden = tuple(
                symbol
                for base in class_fact.bases
                for symbol in base.symbols
                if symbol.value.startswith("app.")
            )
            if forbidden:
                findings.append(
                    _finding(
                        SCHEMA_INHERITANCE_RULE_ID,
                        target.module_id,
                        class_fact.symbol_id,
                        class_fact.id,
                        class_fact.location,
                        "schema.field_inheritance",
                        forbidden[0].value,
                    )
                )
        if findings:
            return RuleEvaluation(
                SCHEMA_INHERITANCE_RULE_ID, target, RuleVerdict.FAIL, tuple(findings)
            )
        return RuleEvaluation(SCHEMA_INHERITANCE_RULE_ID, target, RuleVerdict.PASS, ())


def model_shape_rule_definitions() -> tuple[RuleDefinition, ...]:
    requirements = RuleRequirements(frozenset(), AnalysisStage.FACTS_READY, False, False)
    rows = (
        (
            DTO_RULE_ID,
            "DTO 깊은 불변성",
            "내부 DTO는 frozen dataclass와 변경 불가능한 필드 타입을 사용하세요.",
            ImmutableDtoRule(),
            "dto",
        ),
        (
            DTO_NAME_RULE_ID,
            "DTO 역할 이름",
            "내부 DTO 이름은 Data, Result 또는 Row로 역할을 드러내세요.",
            DtoNameRule(),
            "dto_name",
        ),
        (
            SNAPSHOT_RULE_ID,
            "저장 Snapshot 위치와 버전",
            "저장 Snapshot은 전용 역할에 두고 class 이름에 버전을 표시하세요.",
            SnapshotPlacementRule(),
            "snapshot",
        ),
        (
            SCHEMA_CONFIG_RULE_ID,
            "HTTP Schema 설정",
            "요청과 응답 Schema는 지정된 설정을 직접 선언하세요.",
            SchemaConfigRule(),
            "schema_config",
        ),
        (
            SCHEMA_INHERITANCE_RULE_ID,
            "업무 Schema 필드 상속 금지",
            "업무 Schema는 BaseModel을 직접 상속하고 API 필드를 직접 선언하세요.",
            SchemaInheritanceRule(),
            "schema_inheritance",
        ),
    )
    return tuple(
        RuleDefinition(
            rule_id,
            RULE_VERSION,
            title,
            help_text,
            RuleTarget.MODULE,
            requirements,
            ChangeImpact.SELF,
            implementation,
            (f"tests/fixtures/rules/{folder}/compliant.py",),
            (f"tests/fixtures/rules/{folder}/violation.py",),
        )
        for rule_id, title, help_text, implementation, folder in rows
    )
