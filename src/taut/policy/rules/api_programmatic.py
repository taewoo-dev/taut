from __future__ import annotations

from taut.domain.evaluations import EvaluationReason, RuleTargetRef
from taut.domain.facts import CallFact, ExpressionSummary
from taut.domain.findings import Finding
from taut.domain.ids import RuleId
from taut.policy.context import PolicyContext
from taut.policy.rules.helpers import build_policy_finding


def programmatic_route_evidence(
    rule_id: RuleId,
    target: RuleTargetRef,
    context: PolicyContext,
) -> tuple[tuple[Finding, ...], tuple[EvaluationReason, ...]]:
    if target.module_id is None:
        return (), ()
    functions = {
        function.symbol_id: function
        for module_id in context.model.modules()
        for function in context.model.module(module_id).functions
    }
    findings: list[Finding] = []
    gaps: list[EvaluationReason] = []
    for call in context.model.calls_in(target.module_id):
        symbol = call.ref.symbol
        if symbol is None or symbol.value.rsplit(".", maxsplit=1)[-1] != "add_api_route":
            continue
        endpoint = _argument(call, "endpoint") or _positional(call, 1)
        endpoint_symbols = endpoint.symbols if endpoint is not None else ()
        function = next(
            (functions[candidate] for candidate in endpoint_symbols if candidate in functions),
            None,
        )
        if function is None:
            gaps.append(
                EvaluationReason(
                    "unresolved_endpoint",
                    f"{call.ref.written_name}의 endpoint 함수를 확정하지 못했습니다.",
                )
            )
            continue
        if not function.has_docstring:
            findings.append(
                build_policy_finding(
                    rule_id,
                    target.module_id,
                    function.symbol_id,
                    function.id,
                    function.location,
                    "api.endpoint_docstring_missing",
                    "docstring",
                )
            )
        for keyword, message_key in (
            ("responses", "api.responses_missing"),
            ("response_model", "api.response_model_missing"),
        ):
            if _argument(call, keyword) is None and not call.has_keyword_unpack:
                findings.append(
                    build_policy_finding(
                        rule_id,
                        target.module_id,
                        function.symbol_id,
                        call.id,
                        call.location,
                        message_key,
                        keyword,
                    )
                )
            elif _argument(call, keyword) is None:
                gaps.append(
                    EvaluationReason(
                        "unresolved_mapping",
                        f"{function.symbol_id.value}의 {keyword} mapping을 확정하지 못했습니다.",
                    )
                )
    return tuple(findings), tuple(gaps)


def _argument(call: CallFact, name: str) -> ExpressionSummary | None:
    return next((item.value for item in call.arguments if item.name == name), None)


def _positional(call: CallFact, position: int) -> ExpressionSummary | None:
    return next(
        (item.value for item in call.arguments if item.name is None and item.position == position),
        None,
    )
