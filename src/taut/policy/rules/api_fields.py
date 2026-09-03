"""Public Pydantic field documentation policy."""

from __future__ import annotations

from taut.analysis.framework.pydantic import PYDANTIC_FIELDS, PydanticFieldFact
from taut.domain.evaluations import EvaluationReason, RuleTargetRef, RuleVerdict
from taut.domain.facts import ResolutionState
from taut.domain.findings import Finding
from taut.domain.ids import RuleId
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleEvaluation
from taut.policy.rules.api_field_metadata import field_metadata_names, is_base_model
from taut.policy.rules.helpers import build_policy_finding, target_uncertainty

FIELD_RULE_ID = RuleId("API002")
FIELD_RULE_VERSION = 2


class PublicFieldDocumentationRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("API002 requires a module target")
        role = context.classification.get(target.module_id).role
        if role not in context.policy.code.schema_roles:
            return RuleEvaluation(FIELD_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        uncertainty = target_uncertainty(FIELD_RULE_ID, target, context)
        if uncertainty is not None:
            return uncertainty
        module = context.model.module(target.module_id)
        classes = {
            class_fact.symbol_id: class_fact
            for class_fact in module.classes
            if is_base_model(class_fact)
        }
        if not classes:
            return RuleEvaluation(FIELD_RULE_ID, target, RuleVerdict.PASS, ())
        if PYDANTIC_FIELDS not in context.model.capabilities():
            return RuleEvaluation(
                FIELD_RULE_ID,
                target,
                RuleVerdict.INDETERMINATE,
                (),
                EvaluationReason(
                    "missing_capability",
                    f"provider capability {PYDANTIC_FIELDS} is unavailable.",
                ),
            )
        findings: list[Finding] = []
        coverage_gaps: list[EvaluationReason] = []
        provider_fields = {
            item.field.id: item
            for item in context.model.capability_values(PYDANTIC_FIELDS)
            if isinstance(item, PydanticFieldFact) and item.module_id == target.module_id
        }
        for field in module.fields:
            if (
                field.owner_symbol not in classes
                or field.name.startswith("_")
                or field.name == "model_config"
            ):
                continue
            provider_field = provider_fields.get(field.id)
            if (
                provider_field is not None
                and provider_field.declaration_ref is not None
                and provider_field.declaration_ref.state is not ResolutionState.RESOLVED
            ):
                coverage_gaps.append(
                    EvaluationReason(
                        "uncertain_field_declaration",
                        f"{field.symbol_id.value}의 Field 선언을 확정하지 못했습니다.",
                    )
                )
                continue
            names = field_metadata_names(field, module.calls)
            missing: list[str] = []
            if names is None:
                missing.extend(("description", "examples"))
            else:
                if "description" not in names:
                    missing.append("description")
                if (
                    "examples" not in names
                    and field.owner_symbol not in context.policy.code.generic_schema_bases
                ):
                    missing.append("examples")
            if missing:
                findings.append(
                    build_policy_finding(
                        FIELD_RULE_ID,
                        target.module_id,
                        field.owner_symbol,
                        field.id,
                        field.location,
                        "api.field_metadata_missing",
                        ",".join(missing),
                        rule_version=FIELD_RULE_VERSION,
                    )
                )
        gaps = tuple(sorted(set(coverage_gaps), key=lambda item: item.message))
        if findings:
            return RuleEvaluation(
                FIELD_RULE_ID,
                target,
                RuleVerdict.FAIL,
                tuple(findings),
                coverage_gaps=gaps,
            )
        if gaps:
            return RuleEvaluation(
                FIELD_RULE_ID, target, RuleVerdict.INDETERMINATE, (), gaps[0], gaps
            )
        return RuleEvaluation(FIELD_RULE_ID, target, RuleVerdict.PASS, ())
