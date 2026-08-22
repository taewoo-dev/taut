from __future__ import annotations

from taut.analysis.framework.sqlalchemy_facts import SQLALCHEMY_RAW_SQL, SQLAlchemyRawSQLFact
from taut.configuration.manifest import Role
from taut.domain.evaluations import ChangeImpact, RuleTarget, RuleTargetRef, RuleVerdict
from taut.domain.facts import (
    AnalysisStage,
    CallFact,
    ExpressionSummary,
)
from taut.domain.findings import EvidenceItem, Finding
from taut.domain.ids import FactId, ModuleId, RuleId, SymbolId
from taut.domain.location import SourceRange
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import (
    build_finding,
    module_fact_uncertainty,
    uncertain_provider_evaluation,
)

RELATIONSHIP_RULE_ID = RuleId("ORM001")
DB_ENUM_RULE_ID = RuleId("ORM002")
DATETIME_RULE_ID = RuleId("DB001")
RAW_SQL_RULE_ID = RuleId("SQL001")
RULE_VERSION = 4


def _finding(
    rule_id: RuleId,
    module_id: ModuleId,
    enclosing_symbol: SymbolId | None,
    subject: FactId,
    location: SourceRange,
    message_key: str,
    kind: str,
) -> Finding:
    return build_finding(
        rule_id=rule_id,
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


def _call_symbol(call: CallFact) -> str:
    return call.ref.symbol.value if call.ref.symbol is not None else ""


def _keyword(call: CallFact, name: str) -> ExpressionSummary | None:
    return next((item.value for item in call.arguments if item.name == name), None)


class RelationshipLoadingRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("ORM001 requires a module target")
        uncertain = module_fact_uncertainty(RELATIONSHIP_RULE_ID, target, context, target.module_id)
        if uncertain is not None:
            return uncertain
        role = context.classification.get(target.module_id).role
        if role not in context.policy.code.model_roles:
            return RuleEvaluation(RELATIONSHIP_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        findings: list[Finding] = []
        for call in context.model.module(target.module_id).calls:
            if _call_symbol(call).rsplit(".", maxsplit=1)[-1] != "relationship":
                continue
            lazy = _keyword(call, "lazy")
            value = (lazy.literal_value or "").strip("'\"") if lazy is not None else ""
            if value not in {"raise", "raise_on_sql"}:
                findings.append(
                    _finding(
                        RELATIONSHIP_RULE_ID,
                        target.module_id,
                        call.enclosing_symbol,
                        call.id,
                        call.location,
                        "orm.relationship_loading",
                        value or "missing",
                    )
                )
        if findings:
            return RuleEvaluation(RELATIONSHIP_RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(RELATIONSHIP_RULE_ID, target, RuleVerdict.PASS, ())


def _enum_constructor(call: CallFact) -> bool:
    return _call_symbol(call) in {
        "sqlalchemy.Enum",
        "sqlalchemy.sql.sqltypes.Enum",
        "sqlalchemy.types.Enum",
    }


def _first_enum_symbol(call: CallFact) -> SymbolId | None:
    first = next((item.value for item in call.arguments if item.name is None), None)
    if first is None:
        return None
    return next((symbol for symbol in first.symbols if symbol.value.startswith("app.")), None)


class DatabaseEnumRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("ORM002 requires a module target")
        uncertain = module_fact_uncertainty(DB_ENUM_RULE_ID, target, context, target.module_id)
        if uncertain is not None:
            return uncertain
        role = context.classification.get(target.module_id).role
        if role not in context.policy.code.model_roles:
            return RuleEvaluation(DB_ENUM_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        findings: list[Finding] = []
        for call in context.model.module(target.module_id).calls:
            if not _enum_constructor(call):
                continue
            enum_symbol = _first_enum_symbol(call)
            missing: list[str] = []
            name = _keyword(call, "name")
            values = _keyword(call, "values_callable")
            native = _keyword(call, "native_enum")
            if name is None or name.literal_kind != "str" or not name.literal_value:
                missing.append("name")
            if values is None or ".value" not in values.written:
                missing.append("values_callable")
            if native is None or native.literal_kind != "bool":
                missing.append("native_enum")
            elif native.literal_value == "False":
                if not context.symbol_in(
                    enum_symbol, context.policy.code.native_enum_false_exceptions
                ):
                    missing.append("native_enum=True")
                constraint = _keyword(call, "create_constraint")
                if not context.symbol_in(
                    enum_symbol, context.policy.code.native_enum_no_constraint_exceptions
                ) and (constraint is None or constraint.literal_value != "True"):
                    missing.append("create_constraint=True")
            if missing:
                findings.append(
                    _finding(
                        DB_ENUM_RULE_ID,
                        target.module_id,
                        call.enclosing_symbol,
                        call.id,
                        call.location,
                        "orm.enum_contract",
                        ",".join(missing),
                    )
                )
        if findings:
            return RuleEvaluation(DB_ENUM_RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(DB_ENUM_RULE_ID, target, RuleVerdict.PASS, ())


class TimezoneColumnRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("DB001 requires a module target")
        uncertain = module_fact_uncertainty(DATETIME_RULE_ID, target, context, target.module_id)
        if uncertain is not None:
            return uncertain
        role = context.classification.get(target.module_id).role
        if role not in context.policy.code.model_roles:
            return RuleEvaluation(DATETIME_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        findings: list[Finding] = []
        for call in context.model.module(target.module_id).calls:
            name = _call_symbol(call).rsplit(".", maxsplit=1)[-1]
            if name not in {"DateTime", "TIMESTAMP"}:
                continue
            timezone = _keyword(call, "timezone")
            if timezone is None or timezone.literal_value != "True":
                findings.append(
                    _finding(
                        DATETIME_RULE_ID,
                        target.module_id,
                        call.enclosing_symbol,
                        call.id,
                        call.location,
                        "database.timezone_missing",
                        "timezone=True",
                    )
                )
        if findings:
            return RuleEvaluation(DATETIME_RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(DATETIME_RULE_ID, target, RuleVerdict.PASS, ())


class RawSqlRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("SQL001 requires a module target")
        module = context.model.module(target.module_id)
        uncertain = module_fact_uncertainty(RAW_SQL_RULE_ID, target, context, target.module_id)
        if uncertain is not None:
            return uncertain
        role = context.classification.get(target.module_id).role
        boundaries = context.policy.boundaries
        sqlalchemy_relevant = SQLALCHEMY_RAW_SQL in context.model.capabilities() or any(
            call.ref.symbol is not None and call.ref.symbol.value.startswith("sqlalchemy.")
            for call in module.calls
        )
        if sqlalchemy_relevant:
            provider_uncertain = uncertain_provider_evaluation(
                RAW_SQL_RULE_ID,
                target,
                context,
                (SQLALCHEMY_RAW_SQL,),
                target.module_id,
                require_capabilities=True,
            )
            if provider_uncertain is not None:
                return provider_uncertain
        provider_calls = {
            fact.call.id: fact
            for fact in context.model.capability_values(SQLALCHEMY_RAW_SQL)
            if isinstance(fact, SQLAlchemyRawSQLFact) and fact.module_id == target.module_id
        }
        findings: list[Finding] = []
        for call in module.calls:
            provider_fact = provider_calls.get(call.id)
            if (
                provider_fact is not None
                and provider_fact.operation
                in {
                    "execute",
                    "exec_driver_sql",
                }
                and (provider_fact.is_literal or provider_fact.is_dynamic)
            ):
                findings.append(
                    _finding(
                        RAW_SQL_RULE_ID,
                        target.module_id,
                        call.enclosing_symbol,
                        call.id,
                        call.location,
                        "database.raw_sql_execution",
                        provider_fact.operation,
                    )
                )
                continue
            symbol = call.ref.symbol
            if (
                symbol is not None
                and symbol in boundaries.raw_query_wrappers
                and call.enclosing_symbol != symbol
            ):
                violation = self._raw_query_call_violation(call, role, context)
                if violation is not None:
                    findings.append(
                        _finding(
                            RAW_SQL_RULE_ID,
                            target.module_id,
                            call.enclosing_symbol,
                            call.id,
                            call.location,
                            "database.raw_query_contract",
                            violation,
                        )
                    )
            if symbol is not None and symbol in boundaries.raw_sql_calls:
                if self._inside_approved_wrapper(call, role, context) or self._schema_expression(
                    call,
                    module.calls,
                    role,
                    context,
                ):
                    continue
                findings.append(
                    _finding(
                        RAW_SQL_RULE_ID,
                        target.module_id,
                        call.enclosing_symbol,
                        call.id,
                        call.location,
                        "database.raw_sql",
                        symbol.value,
                    )
                )
                continue
            if provider_fact is None and self._direct_string_execution(call, context):
                findings.append(
                    _finding(
                        RAW_SQL_RULE_ID,
                        target.module_id,
                        call.enclosing_symbol,
                        call.id,
                        call.location,
                        "database.raw_sql_execution",
                        call.ref.symbol.value if call.ref.symbol is not None else "",
                    )
                )
        if findings:
            return RuleEvaluation(RAW_SQL_RULE_ID, target, RuleVerdict.FAIL, tuple(findings))
        return RuleEvaluation(RAW_SQL_RULE_ID, target, RuleVerdict.PASS, ())

    @staticmethod
    def _raw_query_call_violation(
        call: CallFact,
        role: Role | None,
        context: PolicyContext,
    ) -> str | None:
        if role not in context.policy.boundaries.raw_query_roles:
            return f"role:{role.value if role is not None else 'missing'}"
        arguments = {argument.name: argument.value for argument in call.arguments if argument.name}
        missing = sorted({"name", "parameters", "statement"}.difference(arguments))
        if missing:
            return f"missing:{','.join(missing)}"
        name = arguments["name"]
        if name.literal_kind != "str" or not (name.literal_value or "").strip("'\""):
            return "name:not_fixed"
        statement = arguments["statement"]
        if statement.literal_kind != "str" or not (statement.literal_value or "").strip("'\""):
            return "statement:not_fixed"
        return None

    @staticmethod
    def _inside_approved_wrapper(
        call: CallFact,
        role: Role | None,
        context: PolicyContext,
    ) -> bool:
        boundaries = context.policy.boundaries
        return (
            role in boundaries.raw_query_roles
            and call.enclosing_symbol in boundaries.raw_query_wrappers
        )

    @staticmethod
    def _schema_expression(
        call: CallFact,
        calls: tuple[CallFact, ...],
        role: Role | None,
        context: PolicyContext,
    ) -> bool:
        boundaries = context.policy.boundaries
        first = next((argument.value for argument in call.arguments if argument.name is None), None)
        if role not in boundaries.schema_sql_roles or first is None:
            return False
        raw_symbols = set(boundaries.raw_sql_calls)
        for parent in calls:
            if parent.id == call.id or not _range_contains(parent.location, call.location):
                continue
            if parent.ref.symbol in boundaries.schema_sql_parent_calls:
                return True
            for argument in parent.arguments:
                if (
                    first.literal_kind == "str"
                    and argument.name in boundaries.schema_sql_argument_names
                    and raw_symbols.intersection(argument.value.symbols)
                ):
                    return True
        return False

    @staticmethod
    def _direct_string_execution(call: CallFact, context: PolicyContext) -> bool:
        boundaries = context.policy.boundaries
        if call.ref.symbol is None:
            return False
        method = call.ref.symbol.value.rsplit(".", maxsplit=1)[-1]
        if method not in boundaries.raw_sql_execution_methods:
            return False
        first = next((argument.value for argument in call.arguments if argument.name is None), None)
        if first is None or not (first.literal_kind == "str" or first.is_dynamic_string):
            return False
        # SQL execution is recognized only through the resolved SQLAlchemy
        # symbol contract; receiver spelling is not a semantic signal.
        return call.ref.symbol.value.startswith("sqlalchemy.")


def _range_contains(outer: SourceRange, inner: SourceRange) -> bool:
    return (
        outer.path == inner.path
        and (outer.start_line, outer.start_column) <= (inner.start_line, inner.start_column)
        and (inner.end_line, inner.end_column) <= (outer.end_line, outer.end_column)
    )


def persistence_rule_definitions() -> tuple[RuleDefinition, ...]:
    requirements = RuleRequirements(frozenset(), AnalysisStage.FACTS_READY, False, False)
    rows = (
        (
            RELATIONSHIP_RULE_ID,
            "관계의 숨은 DB 조회 금지",
            "relationship은 raise_on_sql 또는 raise 로딩을 명시하세요.",
            RelationshipLoadingRule(),
            "relationship",
        ),
        (
            DB_ENUM_RULE_ID,
            "DB Enum 저장 계약",
            "DB Enum 이름, 저장 값과 native 방식을 모두 명시하세요.",
            DatabaseEnumRule(),
            "db_enum",
        ),
        (
            DATETIME_RULE_ID,
            "시간 DB Column의 timezone",
            "시간 시점 Column에는 timezone=True를 명시하세요.",
            TimezoneColumnRule(),
            "database_time",
        ),
        (
            RAW_SQL_RULE_ID,
            "Raw SQL 통제 경계",
            "일반 코드는 SQLAlchemy 표현식을 사용하고, 필요한 Raw SQL은 "
            "승인된 공용 실행 통로에 두세요.",
            RawSqlRule(),
            "raw_sql",
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
