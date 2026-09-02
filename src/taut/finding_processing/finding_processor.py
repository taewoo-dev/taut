from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass

from taut.configuration.effective_policy import EffectivePolicy, PolicyApproval
from taut.configuration.manifest import ClassificationIndex
from taut.domain.diagnostics import Diagnostic, FindingDisposition
from taut.domain.evaluations import RuleLevel
from taut.domain.findings import EvidenceItem, Finding, FindingSource
from taut.domain.frozen import FrozenMap
from taut.domain.ids import FindingFingerprint, RuleId, SymbolId
from taut.domain.ignores import InlineIgnore
from taut.domain.issues import EngineIssue
from taut.domain.reports import ApprovalAudit, IgnoreAudit

_IGNORE_RULE_ID = RuleId("IGNORE001")
_SUPPRESSION_APPROVAL_KINDS = frozenset(
    {"allow", "entrypoint", "factory", "lazy_import", "security_wrapper"}
)

_MESSAGES = {
    "role.unassigned": "검사 대상 파일에 역할이 지정되지 않았습니다.",
    "time.direct_access": "승인되지 않은 시간 조회 {symbol}을 직접 호출했습니다.",
    "transaction.outside_owner": "{role} 역할에서 {effect}을 호출했습니다.",
    "session.outside_owner": "{role} 역할에서 DB session 생성 함수 {provider}을 호출했습니다.",
    "session.nested": "DB session 안에서 다른 session 생성 함수 {provider}을 호출했습니다.",
    "session.service_parameter": "Service 함수 {symbol}이 DB session을 인자로 받습니다.",
    "session.participant_owns_transaction": (
        "Transaction 참여 함수 {symbol}이 소유자 동작 {operation}을 수행합니다."
    ),
    "boundary.forbidden_import": "{role} 역할이 금지된 {imported}을 import했습니다({boundary}).",
    "architecture.import_direction": (
        "{source_role} 역할이 {target_role} 역할의 {target_module}을 import했습니다."
    ),
    "architecture.import_cycle": "내부 import가 순환합니다: {cycle}",
    "import.local_import": "함수 안에서 {imported}을 import했습니다.",
    "import.relative_import": "상대 import {imported}을 사용했습니다.",
    "size.file_too_large": "파일이 {lines}줄이며 허용된 {maximum}줄을 넘었습니다.",
    "boundary.forbidden_call": "{role} 역할이 금지된 {call}을 호출했습니다({boundary}).",
    "service.external_import": "{role} 역할이 외부 구현 {imported}을 직접 import했습니다.",
    "contract.external_import": "{role} 역할이 외부 자료형 {imported}에 의존합니다.",
    "adapter.database_import": "{role} 역할이 DB 모듈 {imported}을 import했습니다.",
    "adapter.database_call": "Adapter가 DB 함수 {call}을 호출했습니다.",
    "layer.entry_import": "진입점이 금지된 {kind} 의존 {value}을 import했습니다.",
    "layer.entry_call": "진입점이 금지된 {kind} 동작 {value}을 직접 호출했습니다.",
    "layer.service_import": "Service가 금지된 {kind} 의존 {value}을 import했습니다.",
    "layer.service_call": "Service가 금지된 {kind} 동작 {value}을 직접 호출했습니다.",
    "layer.query_import": "Queries가 금지된 {kind} 의존 {value}을 import했습니다.",
    "layer.query_call": "Queries가 금지된 {kind} 동작 {value}을 직접 호출했습니다.",
    "layer.model_import": "Model이 금지된 {kind} 의존 {value}을 import했습니다.",
    "layer.model_call": "Model이 금지된 {kind} 동작 {value}을 직접 호출했습니다.",
    "wiring.constructor_outside_bootstrap": "시작 조립 코드 밖에서 {value} 구현을 만들었습니다.",
    "adapter.external_type_leak": "Adapter 공개 함수에 외부 자료형 {value}이 노출됐습니다.",
    "config.settings_construction": "설정 경계 밖에서 Settings {value}을 직접 만들었습니다.",
    "dependency.outside_entry": "진입점 밖에서 요청 의존성 주입 {value}을 사용했습니다.",
    "test.nested_conftest": "테스트 최상위가 아닌 곳에 {value}이 있습니다.",
    "test.raw_http_client": "테스트가 승인된 test client 대신 {value}을 직접 사용했습니다.",
    "http.timeout_missing": "외부 HTTP client {call}에 timeout이 없습니다.",
    "log.external_call_unwrapped": "외부 호출 {call}이 등록된 기록 문맥 밖에 있습니다.",
    "import.dynamic_import": "운영 코드에서 동적 import {call}을 호출했습니다.",
    "runtime.asyncio_run": "async 함수 안에서 {call}을 호출했습니다.",
    "runtime.hidden_dispatch": "승인되지 않은 축약 실행 {call}을 호출했습니다.",
    "transaction.external_call_while_open": (
        "DB session 또는 transaction을 연 채 외부 호출 {call}을 기다립니다."
    ),
    "transaction.multi_write_unprotected": "여러 DB 쓰기가 transaction 경계 없이 실행됩니다.",
    "async.blocking_call": "async 함수 안에서 동기 호출 {call}을 사용했습니다.",
    "security.direct_access": "{role} 역할에서 보안 관련 함수 {call}을 직접 사용했습니다.",
    "catalog.unknown_risky_call": "위험 여부가 등록되지 않은 외부 호출입니다: {call}",
    "dto.not_frozen": "내부 DTO {symbol}이 불변 dataclass/Pydantic model이 아닙니다.",
    "dto.mutable_field": "내부 DTO {symbol}에 변경 가능한 필드 타입이 있습니다.",
    "dto.name_suffix": "내부 DTO {symbol}의 이름이 역할 suffix를 사용하지 않습니다.",
    "snapshot.wrong_role": "저장 Snapshot {symbol}이 snapshots 역할 밖에 있습니다.",
    "snapshot.version_missing": "저장 Snapshot {symbol} 이름에 버전이 없습니다.",
    "schema.invalid_config": "HTTP Schema {symbol}의 필수 설정이 올바르지 않습니다.",
    "schema.field_inheritance": "HTTP Schema {symbol}이 업무 필드를 상속합니다.",
    "schema.from_internal_missing": "응답 Schema {symbol}에 from_internal이 없습니다.",
    "schema.mapper_missing": "응답 Schema {symbol}에 설정된 변환 메서드가 없습니다.",
    "schema.mapper_not_classmethod": "응답 Schema {symbol}의 변환 메서드는 classmethod여야 합니다.",
    "schema.mapper_input_untyped": "응답 Schema {symbol}의 변환 입력 타입이 없습니다.",
    "schema.mapper_return_untyped": "응답 Schema {symbol}의 변환 반환 타입이 없습니다.",
    "schema.bulk_mapping": "응답 Schema {symbol}이 자동 또는 일괄 복사를 사용합니다.",
    "schema.router_direct_mapping": "Router {symbol}가 응답 Schema {missing}을 직접 조립합니다.",
    "api.endpoint_docstring_missing": "Endpoint {symbol}에 설명이 없습니다.",
    "api.responses_missing": "Endpoint {symbol}에 responses가 없습니다.",
    "api.response_model_missing": "Endpoint {symbol}에 response_model이 없습니다.",
    "api.field_metadata_missing": "공개 API 필드 {symbol}에 {missing}이 없습니다.",
    "api.router_tags_missing": "APIRouter {symbol}와 등록 지점에 tags가 없습니다.",
    "api.query_description_missing": "Query 매개변수 {symbol}에 description이 없습니다.",
    "enum.class_suffix": "Enum {kind}의 class 이름에 Enum suffix가 있습니다.",
    "enum.base_type": "Enum {kind}이 StrEnum을 사용하지 않습니다.",
    "enum.shared_location": "공유 Enum이 중앙 폴더 밖에 있습니다({kind}).",
    "enum.private_import": "내부용 Enum {kind}을 다른 모듈에서 import했습니다.",
    "enum.member_name": "Enum 멤버 이름 형식이 올바르지 않습니다({kind}).",
    "enum.member_value": "Enum 값 형식이 올바르지 않습니다({kind}).",
    "orm.relationship_loading": "relationship 로딩 설정이 올바르지 않습니다({kind}).",
    "orm.enum_contract": "DB Enum 설정이 빠졌거나 올바르지 않습니다({kind}).",
    "database.timezone_missing": "시간 DB Column에 {kind} 설정이 없습니다.",
    "database.raw_sql": "Raw SQL 함수 {kind}을 직접 사용했습니다.",
    "exception.code_missing": "업무 예외 {symbol}에 오류 코드가 없습니다.",
    "exception.code_unregistered": "업무 예외 {symbol}의 오류 코드가 등록표 값이 아닙니다.",
    "exception.code_duplicate": "오류 코드 {kind}를 둘 이상의 업무 예외가 사용합니다.",
    "exception.name_duplicate": "업무 예외 이름 {kind}가 둘 이상의 모듈에 있습니다.",
    "exception.code_unused": "오류 코드 {kind}가 사용 또는 예약되지 않았습니다.",
}


@dataclass(frozen=True)
class FindingProcessingResult:
    diagnostics: tuple[Diagnostic, ...]
    engine_issues: tuple[EngineIssue, ...]
    ignore_audit: IgnoreAudit
    approval_audit: ApprovalAudit


class FindingProcessor:
    def process(
        self,
        *,
        findings: tuple[Finding, ...],
        policy: EffectivePolicy,
        help_by_rule: FrozenMap[RuleId, str],
        ignores: tuple[InlineIgnore, ...],
        classifications: ClassificationIndex | None = None,
        canonicalize: Callable[[SymbolId], SymbolId] | None = None,
        preused_approval_keys: tuple[str, ...] = (),
    ) -> FindingProcessingResult:
        directives = {(item.path, item.line, item.rule_id): item for item in ignores}
        used_ignores: set[str] = set()
        used_approvals = set(preused_approval_keys)
        diagnostics: list[Diagnostic] = []
        for finding in findings:
            key = (
                finding.primary_location.path,
                finding.primary_location.start_line,
                finding.rule_id,
            )
            directive = directives.get(key)
            disposition = FindingDisposition.ACTIVE
            approval = _matching_approval(finding, policy, classifications, canonicalize)
            approved = False
            if directive is not None:
                disposition = FindingDisposition.IGNORED
                used_ignores.add(directive.key)
            elif approval is not None:
                disposition = FindingDisposition.IGNORED
                used_approvals.add(approval.key)
                approved = True
            evidence = finding.evidence
            if approval is not None and approved:
                evidence = (
                    *evidence,
                    EvidenceItem("approval_reason", approval.reason),
                    EvidenceItem("approval_key", approval.key),
                )
            setting = policy.setting(finding.rule_id)
            diagnostics.append(
                Diagnostic(
                    rule_id=finding.rule_id,
                    level=setting.level,
                    message=_render_message(finding),
                    primary_location=finding.primary_location,
                    related_locations=finding.related_locations,
                    evidence=evidence,
                    help=help_by_rule.get(finding.rule_id),
                    fingerprint=finding.fingerprint,
                    disposition=disposition,
                    source=finding.source,
                )
            )

        unused = tuple(item for item in ignores if item.key not in used_ignores)
        for directive in unused:
            diagnostics.append(_unused_ignore_diagnostic(directive, help_by_rule))

        ordered = tuple(
            sorted(
                diagnostics,
                key=lambda item: (
                    item.primary_location.path.value,
                    item.primary_location.start_line,
                    item.primary_location.start_column,
                    item.rule_id.value,
                    item.fingerprint.value,
                ),
            )
        )
        return FindingProcessingResult(
            diagnostics=ordered,
            engine_issues=(),
            ignore_audit=IgnoreAudit(
                used=tuple(sorted(used_ignores)),
                unused=tuple(sorted(item.key for item in unused)),
            ),
            approval_audit=ApprovalAudit(
                used=tuple(sorted(used_approvals)),
                unused=tuple(
                    approval.key
                    for approval in policy.approvals
                    if approval.key not in used_approvals
                ),
            ),
        )


def _matching_approval(
    finding: Finding,
    policy: EffectivePolicy,
    classifications: ClassificationIndex | None,
    canonicalize: Callable[[SymbolId], SymbolId] | None,
) -> PolicyApproval | None:
    if classifications is None:
        return None
    zone = classifications.get(finding.module_id).zone
    symbol = finding.enclosing_symbol or SymbolId(finding.module_id.value)
    canonical = canonicalize(symbol) if canonicalize is not None else symbol
    tokens = {str(value) for _, value in finding.arguments.items() if value is not None}
    for item in finding.evidence:
        if isinstance(item.value, tuple):
            tokens.update(item.value)
        elif item.value is not None:
            tokens.add(str(item.value))
    return next(
        (
            approval
            for approval in policy.approvals
            if approval.kind in _SUPPRESSION_APPROVAL_KINDS
            and approval.rule_id == finding.rule_id
            and (canonicalize(approval.symbol) if canonicalize is not None else approval.symbol)
            == canonical
            and zone in approval.zones
            and (approval.target is None or approval.target in tokens)
        ),
        None,
    )


def _unused_ignore_diagnostic(
    directive: InlineIgnore,
    help_by_rule: FrozenMap[RuleId, str],
) -> Diagnostic:
    digest = hashlib.sha256(directive.key.encode()).hexdigest()
    return Diagnostic(
        rule_id=_IGNORE_RULE_ID,
        level=RuleLevel.ENFORCED,
        message=f"사용되지 않은 ignore 주석입니다: {directive.rule_id.value}",
        primary_location=directive.location,
        related_locations=(),
        evidence=(EvidenceItem("ignored_rule", directive.rule_id.value),),
        help=help_by_rule.get(_IGNORE_RULE_ID),
        fingerprint=FindingFingerprint(digest),
        disposition=FindingDisposition.ACTIVE,
        source=FindingSource.STATIC,
    )


def _render_message(finding: Finding) -> str:
    template = _MESSAGES.get(finding.message_key)
    if template is None:
        return finding.message_key
    return template.format(**dict(finding.arguments.items()))
