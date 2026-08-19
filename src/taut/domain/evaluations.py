from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from taut.domain.frozen import FrozenMap
from taut.domain.ids import FactId, ModuleId, SymbolId


class RuleLevel(StrEnum):
    OFF = "off"
    ADVISORY = "advisory"
    ENFORCED = "enforced"


class RuleTarget(StrEnum):
    MODULE = "module"
    SYMBOL = "symbol"
    CALL = "call"
    OPERATION = "operation"
    PROJECT = "project"


class ChangeImpact(StrEnum):
    SELF = "self"
    DEPENDENTS = "dependents"
    PROJECT = "project"


class RuleVerdict(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True, order=True)
class RuleTargetRef:
    kind: RuleTarget
    module_id: ModuleId | None = None
    symbol_id: SymbolId | None = None
    fact_id: FactId | None = None

    def __post_init__(self) -> None:
        expected: tuple[ModuleId | None, SymbolId | None, FactId | None]
        if self.kind is RuleTarget.PROJECT:
            expected = (None, None, None)
        elif self.kind is RuleTarget.MODULE:
            expected = (self.module_id, None, None)
            if self.module_id is None:
                raise ValueError("module target requires module_id")
        elif self.kind is RuleTarget.SYMBOL:
            expected = (self.module_id, self.symbol_id, None)
            if self.module_id is None or self.symbol_id is None:
                raise ValueError("symbol target requires module_id and symbol_id")
        else:
            expected = (self.module_id, None, self.fact_id)
            if self.module_id is None or self.fact_id is None:
                raise ValueError("call and operation targets require module_id and fact_id")
        actual = (self.module_id, self.symbol_id, self.fact_id)
        if actual != expected:
            raise ValueError(f"invalid identifiers for {self.kind.value} target")


@dataclass(frozen=True, order=True)
class EvaluationReason:
    code: str
    message: str

    def __post_init__(self) -> None:
        if not self.code.strip() or not self.message.strip():
            raise ValueError("evaluation reason code and message cannot be empty")


ScalarParameter = str | int | float | bool | None | tuple[str, ...]


@dataclass(frozen=True)
class RuleSetting:
    level: RuleLevel
    parameters: FrozenMap[str, ScalarParameter]
