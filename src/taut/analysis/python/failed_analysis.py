from __future__ import annotations

from taut.analysis.contracts import SourceInput
from taut.domain.facts import (
    AnalysisStage,
    CompletenessState,
    FactKind,
    IncompleteReason,
    ModuleCompleteness,
    ModuleFacts,
    ModuleIdentity,
)
from taut.domain.frozen import FrozenMap


def failed_facts(source: SourceInput) -> ModuleFacts:
    unavailable = FrozenMap(
        (kind, IncompleteReason("analysis_failed", "파일 분석이 실패했습니다."))
        for kind in FactKind
    )
    return ModuleFacts(
        module=ModuleIdentity(
            id=source.module_id,
            path=source.path,
            kind=source.kind,
            is_policy_target=source.is_policy_target,
            is_package=source.is_package,
            line_count=len(source.content.splitlines()),
        ),
        imports=(),
        definitions=(),
        references=(),
        calls=(),
        decorators=(),
        functions=(),
        classes=(),
        fields=(),
        bindings=(),
        completeness=ModuleCompleteness(
            state=CompletenessState.FAILED,
            stage=AnalysisStage.FAILED,
            available_facts=frozenset(),
            unavailable_facts=unavailable,
        ),
    )
