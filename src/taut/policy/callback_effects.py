from __future__ import annotations

from dataclasses import dataclass

from taut.analysis.semantic_model import SemanticModel
from taut.configuration.catalog import AccessPath, Effect, EffectCatalog
from taut.domain.facts import CallFact, ExpressionSummary, FunctionFact, GuardKind, ResolutionState
from taut.domain.frozen import FrozenMap
from taut.domain.ids import SymbolId


@dataclass(frozen=True)
class CallbackEffectIndex:
    """Specialize exact callbacks invoked by bounded first-party synchronous helpers.

    Bounded to direct parameter calls in undecorated module-level functions.
    Merely accepting or returning a callable does not make a function an invoker.
    """

    functions: FrozenMap[SymbolId, FunctionFact]
    invoked: FrozenMap[SymbolId, frozenset[str]]
    synchronous: FrozenMap[SymbolId, frozenset[str]]

    @classmethod
    def build(cls, model: SemanticModel) -> CallbackEffectIndex:
        functions: dict[SymbolId, FunctionFact] = {}
        invoked: dict[SymbolId, frozenset[str]] = {}
        synchronous: dict[SymbolId, frozenset[str]] = {}
        for module_id in model.modules():
            module = model.module(module_id)
            calls: dict[SymbolId, set[SymbolId]] = {}
            direct: dict[SymbolId, set[SymbolId]] = {}
            reassigned: set[SymbolId] = set()
            for binding in module.bindings:
                if binding.kind != "parameter":
                    reassigned.add(binding.symbol_id)
            for call in module.calls:
                if call.enclosing_symbol is not None and call.ref.symbol is not None:
                    calls.setdefault(call.enclosing_symbol, set()).add(call.ref.symbol)
                    if (
                        call.context.guard is GuardKind.UNCONDITIONAL
                        and not call.enclosing_contexts
                    ):
                        direct.setdefault(call.enclosing_symbol, set()).add(call.ref.symbol)
            for function in module.functions:
                if (
                    function.context.lexical_owner is not None and function.name != "<lambda>"
                ) or function.decorators:
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
                    synchronous[symbol] = frozenset(
                        name
                        for name in names
                        if SymbolId(f"{function.symbol_id.value}.{name}")
                        in direct.get(function.symbol_id, set())
                    )
        return cls(
            FrozenMap(sorted(functions.items())),
            FrozenMap(sorted(invoked.items())),
            FrozenMap(sorted(synchronous.items())),
        )

    def effects(
        self,
        call: CallFact,
        model: SemanticModel,
        catalog: EffectCatalog,
        *,
        definite: bool = False,
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
        parameters = {parameter.name: parameter for parameter in function.parameters}
        values = {parameter.name: parameter.default_expression for parameter in function.parameters}
        supplied: set[str] = set()
        for argument in call.arguments:
            if argument.name is not None:
                parameter = parameters.get(argument.name)
                if parameter is None or parameter.kind in {"positional_only", "var_keyword"}:
                    return frozenset()
                name = argument.name
            elif argument.position < len(positional):
                name = positional[argument.position].name
            else:
                return frozenset()
            if name in supplied:
                return frozenset()
            values[name] = argument.value
            supplied.add(name)
        if any(
            not parameter.has_default
            and parameter.kind not in {"var_positional", "var_keyword"}
            and parameter.name not in supplied
            for parameter in function.parameters
        ):
            return frozenset()
        effects: set[Effect] = set()
        names = self.synchronous[symbol] if definite else self.invoked[symbol]
        for name in names:
            value = values.get(name)
            candidate = argument_symbol(value, model)
            entry = catalog.entries.get(candidate) if candidate is not None else None
            if entry is not None and entry.access_path is AccessPath.DIRECT:
                effects.update(entry.effects)
        return frozenset(effects)


def argument_symbol(value: ExpressionSummary | None, model: SemanticModel) -> SymbolId | None:
    # Expression symbols include bases: require one exact attribute chain, not a
    # catalog symbol merely occurring somewhere inside an argument expression.
    if value is None or value.kind not in {"Name", "Attribute"} or not value.symbols:
        return None
    # A call/subscript in the base can contribute nested symbols even when the
    # outer attribute is unresolved. Bound specialization to dotted names.
    if not all(part.isidentifier() for part in value.written.split(".")):
        return None
    symbols = tuple(model.canonical_symbol(symbol) for symbol in value.symbols)
    leaf = max(symbols, key=lambda symbol: len(symbol.value))
    return (
        leaf
        if all(leaf == symbol or leaf.value.startswith(symbol.value + ".") for symbol in symbols)
        else None
    )
