from __future__ import annotations

from dataclasses import dataclass

from taut.analysis.semantic_model import SemanticModel
from taut.configuration.catalog import AccessPath, Effect, EffectCatalog
from taut.domain.facts import CallFact, FunctionFact, ResolutionState
from taut.domain.frozen import FrozenMap
from taut.domain.ids import SymbolId


@dataclass(frozen=True)
class CallbackEffectIndex:
    """Known callback effects are uncertainty, never proof of synchronous execution.

    Bounded to direct parameter calls in undecorated module-level functions.
    Merely accepting or returning a callable does not make a function an invoker.
    """

    functions: FrozenMap[SymbolId, FunctionFact]
    invoked: FrozenMap[SymbolId, frozenset[str]]

    @classmethod
    def build(cls, model: SemanticModel) -> CallbackEffectIndex:
        functions: dict[SymbolId, FunctionFact] = {}
        invoked: dict[SymbolId, frozenset[str]] = {}
        for module_id in model.modules():
            module = model.module(module_id)
            calls: dict[SymbolId, set[SymbolId]] = {}
            reassigned: set[SymbolId] = set()
            for binding in module.bindings:
                if binding.kind != "parameter":
                    reassigned.add(binding.symbol_id)
            for call in module.calls:
                if call.enclosing_symbol is not None and call.ref.symbol is not None:
                    calls.setdefault(call.enclosing_symbol, set()).add(call.ref.symbol)
            for function in module.functions:
                if function.context.lexical_owner is not None or function.decorators:
                    continue
                symbol = model.canonical_symbol(function.symbol_id)
                names = frozenset(
                    parameter.name
                    for parameter in function.parameters
                    if SymbolId(f"{function.symbol_id.value}.{parameter.name}")
                    in calls.get(function.symbol_id, set()) - reassigned
                )
                if names:
                    functions[symbol] = function
                    invoked[symbol] = names
        return cls(FrozenMap(sorted(functions.items())), FrozenMap(sorted(invoked.items())))

    def effects(
        self, call: CallFact, model: SemanticModel, catalog: EffectCatalog
    ) -> frozenset[Effect]:
        if call.ref.state is not ResolutionState.RESOLVED or call.ref.symbol is None:
            return frozenset()
        symbol = model.canonical_symbol(call.ref.symbol)
        function = self.functions.get(symbol)
        if function is None or function.is_async or call.has_keyword_unpack:
            return frozenset()
        if any(argument.value.kind == "Starred" for argument in call.arguments):
            return frozenset()
        positional = tuple(
            parameter
            for parameter in function.parameters
            if parameter.kind in {"positional_only", "positional_or_keyword"}
        )
        values = {parameter.name: parameter.default_expression for parameter in function.parameters}
        for argument in call.arguments:
            if argument.name is not None:
                values[argument.name] = argument.value
            elif argument.position < len(positional):
                values[positional[argument.position].name] = argument.value
        effects: set[Effect] = set()
        for name in self.invoked[symbol]:
            value = values.get(name)
            if value is None or value.kind not in {"Name", "Attribute"}:
                continue
            for candidate in value.symbols:
                entry = catalog.entries.get(model.canonical_symbol(candidate))
                if entry is not None and entry.access_path is AccessPath.DIRECT:
                    effects.update(entry.effects)
        return frozenset(effects)
