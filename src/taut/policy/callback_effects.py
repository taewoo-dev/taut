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

    Bounded to parameter calls and forwarding through undecorated synchronous helpers.
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
        owned_calls: dict[SymbolId, tuple[CallFact, ...]] = {}
        reassigned_by_owner: dict[SymbolId, set[SymbolId]] = {}
        for module_id in model.modules():
            module = model.module(module_id)
            calls: dict[SymbolId, set[SymbolId]] = {}
            call_facts: dict[SymbolId, list[CallFact]] = {}
            direct: dict[SymbolId, set[SymbolId]] = {}
            reassigned: set[SymbolId] = set()
            for binding in module.bindings:
                if binding.kind != "parameter":
                    reassigned.add(binding.symbol_id)
            for call in module.calls:
                if call.enclosing_symbol is not None and call.ref.symbol is not None:
                    calls.setdefault(call.enclosing_symbol, set()).add(call.ref.symbol)
                    call_facts.setdefault(call.enclosing_symbol, []).append(call)
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
                if function.is_async:
                    continue
                functions[symbol] = function
                owned_calls[symbol] = tuple(call_facts.get(function.symbol_id, ()))
                reassigned_by_owner[symbol] = reassigned
                invoked[symbol] = names
                synchronous[symbol] = frozenset(
                    name
                    for name in names
                    if SymbolId(f"{function.symbol_id.value}.{name}")
                    in direct.get(function.symbol_id, set())
                )
        _propagate_forwarding(
            model, functions, owned_calls, reassigned_by_owner, invoked, synchronous
        )
        return cls(
            FrozenMap(sorted((symbol, functions[symbol]) for symbol in invoked if invoked[symbol])),
            FrozenMap(sorted((symbol, names) for symbol, names in invoked.items() if names)),
            FrozenMap(
                sorted((symbol, synchronous[symbol]) for symbol in invoked if invoked[symbol])
            ),
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
        values = bind_arguments(call, function) if function is not None else None
        if values is None:
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


def _propagate_forwarding(
    model: SemanticModel,
    functions: dict[SymbolId, FunctionFact],
    owned_calls: dict[SymbolId, tuple[CallFact, ...]],
    reassigned_by_owner: dict[SymbolId, set[SymbolId]],
    invoked: dict[SymbolId, frozenset[str]],
    synchronous: dict[SymbolId, frozenset[str]],
) -> None:
    # Monotone finite sets reach a fixed point even for mutually recursive helpers.
    changed = True
    while changed:
        changed = False
        for owner, function in functions.items():
            parameters = {
                SymbolId(f"{function.symbol_id.value}.{parameter.name}"): parameter.name
                for parameter in function.parameters
                if SymbolId(f"{function.symbol_id.value}.{parameter.name}")
                not in reassigned_by_owner[owner]
            }
            if not parameters:
                continue
            for call in owned_calls[owner]:
                if call.ref.state is not ResolutionState.RESOLVED or call.ref.symbol is None:
                    continue
                target = model.canonical_symbol(call.ref.symbol)
                callee = functions.get(target)
                values = bind_arguments(call, callee) if callee is not None else None
                if values is None:
                    continue
                for definite, index in ((False, invoked), (True, synchronous)):
                    if definite and (
                        call.context.guard is not GuardKind.UNCONDITIONAL or call.enclosing_contexts
                    ):
                        continue
                    forwarded = frozenset(
                        parameters[candidate]
                        for name in index[target]
                        if (candidate := argument_symbol(values.get(name), model)) in parameters
                    )
                    updated = index[owner] | forwarded
                    if updated != index[owner]:
                        index[owner] = updated
                        changed = True


def bind_arguments(
    call: CallFact, function: FunctionFact
) -> dict[str, ExpressionSummary | None] | None:
    if function.is_async or call.has_keyword_unpack:
        return None
    if any(argument.value.kind == "Starred" for argument in call.arguments):
        return None
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
                return None
            name = argument.name
        elif argument.position < len(positional):
            name = positional[argument.position].name
        else:
            return None
        if name in supplied:
            return None
        values[name] = argument.value
        supplied.add(name)
    if any(
        not parameter.has_default
        and parameter.kind not in {"var_positional", "var_keyword"}
        and parameter.name not in supplied
        for parameter in function.parameters
    ):
        return None
    return values


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
