from __future__ import annotations

from taut.analysis.framework.pytest_facts import PYTEST_FIXTURES, PytestFixtureFact
from taut.configuration.manifest import Zone
from taut.domain.evaluations import ChangeImpact, RuleTarget, RuleTargetRef, RuleVerdict
from taut.domain.facts import AnalysisStage
from taut.domain.findings import Finding
from taut.domain.ids import RuleId, SymbolId
from taut.domain.location import ProjectPath, SourceRange
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
from taut.policy.rules.helpers import module_fact_uncertainty, unresolved_call_evaluation
from taut.policy.rules.layer_boundaries import (
    RULE_VERSION,
    boundary_result,
    build_boundary_finding,
)

TEST_LAYOUT_RULE_ID = RuleId("TEST001")
TEST_HTTP_RULE_ID = RuleId("TEST002")
_TEST_ZONE = frozenset({Zone("test")})


class TestFixtureLayoutRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("TEST001 requires a module target")
        uncertainty = module_fact_uncertainty(
            TEST_LAYOUT_RULE_ID, target, context, target.module_id
        )
        if uncertainty is not None:
            return uncertainty
        module = context.model.module(target.module_id).module
        path = module.path.value
        if path.rsplit("/", maxsplit=1)[-1] != "conftest.py":
            return RuleEvaluation(TEST_LAYOUT_RULE_ID, target, RuleVerdict.NOT_APPLICABLE, ())
        parent = path.rsplit("/", maxsplit=1)[0] if "/" in path else ""
        allowed = {root.value.rstrip("/") for root in context.policy.code.test_root_paths}
        if parent in allowed:
            return RuleEvaluation(TEST_LAYOUT_RULE_ID, target, RuleVerdict.PASS, ())
        finding = build_boundary_finding(
            TEST_LAYOUT_RULE_ID,
            module_id=target.module_id,
            subject=target.module_id,
            enclosing_symbol=None,
            location=_module_path_location(module.path),
            message_key="test.nested_conftest",
            kind="conftest",
            value=path,
        )
        return RuleEvaluation(TEST_LAYOUT_RULE_ID, target, RuleVerdict.FAIL, (finding,))


def _module_path_location(path: ProjectPath) -> SourceRange:
    return SourceRange(path, 0, 0, 0, 0)


class TestRawHttpRule:
    def evaluate(self, target: RuleTargetRef, context: PolicyContext) -> RuleEvaluation:
        if target.module_id is None:
            raise ValueError("TEST002 requires a module target")
        uncertainty = module_fact_uncertainty(TEST_HTTP_RULE_ID, target, context, target.module_id)
        if uncertainty is not None:
            return uncertainty
        role = context.classification.get(target.module_id).role
        if role in context.policy.code.test_http_fixture_roles:
            return RuleEvaluation(TEST_HTTP_RULE_ID, target, RuleVerdict.PASS, ())
        approved_fixtures = _approved_http_fixtures(context)
        forbidden = set(context.policy.code.raw_test_http_calls).union(
            context.policy.code.raw_test_http_client_constructors
        )
        uncertainty = unresolved_call_evaluation(
            TEST_HTTP_RULE_ID, target, context, target.module_id, tuple(forbidden)
        )
        if uncertainty is not None:
            return uncertainty
        findings: list[Finding] = []
        for call in context.model.calls_in(target.module_id):
            symbol = call.ref.symbol
            if symbol is None or symbol not in forbidden:
                continue
            if _uses_approved_fixture(
                call.ref.written_name,
                call.enclosing_symbol,
                context,
                approved_fixtures,
            ):
                continue
            findings.append(
                build_boundary_finding(
                    TEST_HTTP_RULE_ID,
                    module_id=target.module_id,
                    subject=call.id,
                    enclosing_symbol=call.enclosing_symbol,
                    location=call.location,
                    message_key="test.raw_http_client",
                    kind="raw_http",
                    value=symbol.value,
                )
            )
        return boundary_result(TEST_HTTP_RULE_ID, target, findings)


def _approved_http_fixtures(context: PolicyContext) -> frozenset[str]:
    fixtures = tuple(
        fact
        for fact in context.model.capability_values(PYTEST_FIXTURES)
        if isinstance(fact, PytestFixtureFact)
    )
    approved = {
        fixture.name
        for fixture in fixtures
        if context.classification.get(fixture.module_id).role
        in context.policy.code.test_http_fixture_roles
        or context.symbol_in(fixture.symbol, context.policy.code.test_http_fixture_symbols)
    }
    changed = True
    while changed:
        changed = False
        for fixture in fixtures:
            if fixture.name in approved or not any(
                dependency in approved for dependency in fixture.dependencies
            ):
                continue
            approved.add(fixture.name)
            changed = True
    return frozenset(approved)


def _uses_approved_fixture(
    written_name: str,
    enclosing_symbol: SymbolId | None,
    context: PolicyContext,
    approved: frozenset[str],
) -> bool:
    if enclosing_symbol is None or "." not in written_name:
        return False
    receiver = written_name.split(".", 1)[0]
    if receiver not in approved:
        return False
    function = next(
        (
            item
            for module_id in context.model.modules()
            for item in context.model.module(module_id).functions
            if item.symbol_id == enclosing_symbol
        ),
        None,
    )
    return function is not None and any(
        parameter.name == receiver for parameter in function.parameters
    )


def test_boundary_rule_definitions() -> tuple[RuleDefinition, ...]:
    requirements = RuleRequirements(frozenset(), AnalysisStage.FACTS_READY, False, False)
    return (
        RuleDefinition(
            TEST_LAYOUT_RULE_ID,
            RULE_VERSION,
            "하위 conftest 금지",
            "공유 fixture는 설정한 테스트 최상위 conftest.py 한 곳에 두세요.",
            RuleTarget.MODULE,
            requirements,
            ChangeImpact.SELF,
            TestFixtureLayoutRule(),
            ("tests/fixtures/rules/test_layout/compliant.py",),
            ("tests/fixtures/rules/test_layout/violation.py",),
            applies_to_zones=_TEST_ZONE,
        ),
        RuleDefinition(
            TEST_HTTP_RULE_ID,
            RULE_VERSION,
            "테스트 raw HTTP client 금지",
            "테스트는 raw HTTP client 대신 저장소가 승인한 test client를 사용하세요.",
            RuleTarget.MODULE,
            requirements,
            ChangeImpact.SELF,
            TestRawHttpRule(),
            ("tests/fixtures/rules/test_http/compliant.py",),
            ("tests/fixtures/rules/test_http/violation.py",),
            applies_to_zones=_TEST_ZONE,
        ),
    )
