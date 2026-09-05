from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from taut.analysis.semantic_model import SemanticModel, SnapshotSemanticModel
from taut.configuration.effective_policy import EffectivePolicy
from taut.domain.facts import ClassFact, ModuleFacts
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId, SymbolId


class ExceptionContext(Protocol):
    @property
    def model(self) -> SemanticModel: ...
    @property
    def policy(self) -> EffectivePolicy: ...
    def matching_symbol(
        self, symbol: SymbolId | None, candidates: frozenset[SymbolId]
    ) -> SymbolId | None: ...


@dataclass(frozen=True)
class ExceptionModuleEvidence:
    module: ModuleFacts
    classes: FrozenMap[SymbolId, ClassFact]
    referenced_codes: frozenset[SymbolId]


@dataclass
class ExceptionEvidenceCache:
    entries: dict[ModuleId, ExceptionModuleEvidence] = field(
        default_factory=lambda: dict[ModuleId, ExceptionModuleEvidence]()
    )
    identity: object = None

    def fork(self) -> ExceptionEvidenceCache:
        return ExceptionEvidenceCache(dict(self.entries), self.identity)

    def prepare(self, context: ExceptionContext) -> None:
        model = context.model
        canonical = (
            model.canonical_symbols if type(model) is SnapshotSemanticModel else model.snapshot_id
        )
        identity = (canonical, context.policy.code.error_code_enum_symbols)
        if self.identity != identity:
            self.entries.clear()
            self.identity = identity
        current = frozenset(model.modules())
        for module_id in tuple(self.entries):
            if module_id not in current or self.entries[module_id].module is not model.module(
                module_id
            ):
                del self.entries[module_id]

    def collect(self, context: ExceptionContext, module: ModuleFacts) -> ExceptionModuleEvidence:
        old = self.entries.get(module.module.id)
        if old is not None and old.module is module:
            return old
        evidence = ExceptionModuleEvidence(
            module,
            FrozenMap(
                {context.model.canonical_symbol(item.symbol_id): item for item in module.classes}
            ),
            frozenset(
                context.model.canonical_symbol(symbol)
                for reference in module.references
                if (symbol := reference.ref.symbol) is not None
                and context.matching_symbol(symbol, context.policy.code.error_code_enum_symbols)
            ),
        )
        self.entries[module.module.id] = evidence
        return evidence
