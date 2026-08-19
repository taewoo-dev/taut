from __future__ import annotations

from taut.configuration.effective_policy import EffectivePolicy
from taut.configuration.manifest import ClassificationIndex
from taut.domain.evaluations import RuleLevel
from taut.domain.ids import RuleId


def validate_classification_for_policy(
    classifications: ClassificationIndex,
    policy: EffectivePolicy,
) -> None:
    setting = policy.setting(RuleId("ARCH001"))
    if setting.level is RuleLevel.OFF:
        return
    for classification in classifications.modules.values():
        if classification.role is None:
            continue
        if classification.role not in policy.allowed_imports:
            raise ValueError(f"{classification.role.value}: architecture.allow 항목이 없습니다.")
