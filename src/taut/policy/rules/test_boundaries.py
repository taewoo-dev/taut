from __future__ import annotations

from taut.configuration.manifest import Zone
from taut.domain.evaluations import ChangeImpact, RuleTarget, RuleTargetRef, RuleVerdict
from taut.domain.facts import AnalysisStage
from taut.domain.findings import Finding
from taut.domain.ids import RuleId
from taut.domain.location import ProjectPath, SourceRange
from taut.policy.context import PolicyContext
from taut.policy.rule import RuleDefinition, RuleEvaluation, RuleRequirements
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
        role = context.classification.get(target.module_id).role
        if role in context.policy.code.test_http_fixture_roles:
            return RuleEvaluation(TEST_HTTP_RULE_ID, target, RuleVerdict.PASS, ())
        forbidden = set(context.policy.code.raw_test_http_calls).union(
            context.policy.code.raw_test_http_client_constructors
        )
        findings: list[Finding] = []
        for call in context.model.calls_in(target.module_id):
            symbol = call.ref.symbol
            if symbol is None or symbol not in forbidden:
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
