from __future__ import annotations

from dataclasses import dataclass

from taut.analysis.framework.fastapi import FASTAPI_RESPONSE_MODELS, FastAPIResponseModelFact
from taut.analysis.framework.pydantic import PYDANTIC_MODELS
from taut.analysis.framework.pydantic_facts import PydanticModelFact
from taut.analysis.semantic_model import SemanticModel
from taut.configuration.effective_policy import EffectivePolicy
from taut.configuration.manifest import ClassificationIndex
from taut.domain.facts import ClassFact
from taut.domain.frozen import FrozenMap
from taut.domain.ids import SymbolId
from taut.domain.symbol_contracts import ContractKind


@dataclass(frozen=True)
class SymbolContractIndex:
    """Class-level contracts kept separate from module architecture roles."""

    values: FrozenMap[SymbolId, frozenset[ContractKind]]

    @classmethod
    def build(
        cls,
        model: SemanticModel,
        classification: ClassificationIndex,
        policy: EffectivePolicy,
    ) -> SymbolContractIndex:
        classes = {
            model.canonical_symbol(item.symbol_id): item
            for module_id in model.modules()
            for item in model.module(module_id).classes
        }
        bases = {
            symbol: frozenset(
                model.canonical_symbol(base_symbol)
                for base in item.bases
                for base_symbol in base.symbols
            )
            for symbol, item in classes.items()
        }

        def inherits(
            symbol: SymbolId,
            wanted: frozenset[SymbolId],
            visiting: frozenset[SymbolId] = frozenset(),
        ) -> bool:
            canonical_wanted = frozenset(model.canonical_symbol(item) for item in wanted)
            if bases.get(symbol, frozenset()).intersection(canonical_wanted):
                return True
            if symbol in visiting:
                return False
            return any(
                parent in classes and inherits(parent, wanted, visiting | {symbol})
                for parent in bases.get(symbol, frozenset())
            )

        enum_bases = frozenset(
            {
                SymbolId("enum.Enum"),
                SymbolId("enum.IntEnum"),
                SymbolId("enum.StrEnum"),
            }
        )
        pydantic_models = {
            model.canonical_symbol(fact.symbol)
            for fact in model.capability_values(PYDANTIC_MODELS)
            if isinstance(fact, PydanticModelFact)
        }
        response_models = {
            model.canonical_symbol(fact.model)
            for fact in model.capability_values(FASTAPI_RESPONSE_MODELS)
            if isinstance(fact, FastAPIResponseModelFact) and fact.model is not None
        }
        response_models.update(
            model.canonical_symbol(candidate)
            for module_id in model.modules()
            for call in model.calls_in(module_id)
            if call.ref.symbol is not None
            and call.ref.symbol.value.rsplit(".", maxsplit=1)[-1] == "add_api_route"
            for argument in call.arguments
            if argument.name == "response_model"
            for candidate in argument.value.symbols
        )
        result: list[tuple[SymbolId, frozenset[ContractKind]]] = []
        for symbol, item in classes.items():
            role = classification.get(item.module_id).role
            kinds: set[ContractKind] = set()
            module = model.module(item.module_id)
            is_dataclass = any(
                decorator.decorated_symbol == item.symbol_id
                and decorator.ref.symbol == SymbolId("dataclasses.dataclass")
                for decorator in module.decorators
            )
            role_dto = role in policy.code.dto_roles and (
                is_dataclass
                or symbol in pydantic_models
                or item.name.endswith(policy.code.dto_name_suffixes)
            )
            if role_dto or inherits(symbol, policy.code.dto_base_symbols):
                kinds.add(ContractKind.DTO)
            if role in policy.code.schema_roles:
                if item.name.endswith(("Request", "RequestModel")):
                    kinds.add(ContractKind.REQUEST)
                if item.name.endswith(("Response", "ResponseModel")) or symbol in response_models:
                    kinds.add(ContractKind.RESPONSE)
            if "Snapshot" in item.name:
                kinds.add(ContractKind.SNAPSHOT)
            if inherits(symbol, policy.code.exception_base_symbols):
                kinds.add(ContractKind.EXCEPTION)
            if inherits(symbol, enum_bases):
                kinds.add(ContractKind.ENUM)
            if kinds:
                result.append((symbol, frozenset(kinds)))
        return cls(FrozenMap(result))

    def has(self, class_fact: ClassFact, kind: ContractKind) -> bool:
        return kind in self.values.get(class_fact.symbol_id, frozenset())
