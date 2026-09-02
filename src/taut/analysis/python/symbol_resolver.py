from __future__ import annotations

import ast
from collections import defaultdict
from collections.abc import Sequence

from taut.analysis.contracts import SourceInput
from taut.analysis.module_identity import absolute_import_base
from taut.analysis.python.fact_ids import next_fact_id
from taut.analysis.python.identity import PYTHON_AST_IDENTITY
from taut.analysis.python.resolver_primitives import Scope, node_range, written_name
from taut.analysis.python.scope_flow import BindingState, PythonScopeFlow
from taut.domain.facts import FactKind, ResolutionState, SymbolRef
from taut.domain.ids import FactId, SymbolId
from taut.domain.location import SourceRange
from taut.domain.provenance import Provenance

_BUILTINS = frozenset(
    {
        "__import__",
        "bool",
        "dict",
        "enumerate",
        "float",
        "getattr",
        "int",
        "len",
        "list",
        "max",
        "min",
        "print",
        "range",
        "set",
        "str",
        "sum",
        "super",
        "tuple",
        "zip",
    }
)


class PythonSymbolResolver(PythonScopeFlow):
    occurrences: dict[tuple[str, str, str], int]

    def __init__(self, source: SourceInput) -> None:
        self.source = source
        self.current_scope: SymbolId | None = None
        self.scopes: dict[SymbolId | None, Scope] = {None: Scope(None, None, "module")}
        self.bindings: dict[SymbolId | None, dict[str, SymbolId]] = defaultdict(dict)
        self.binding_states: dict[SymbolId | None, dict[str, BindingState]] = defaultdict(dict)
        self.type_bindings: dict[SymbolId | None, dict[str, SymbolId]] = defaultdict(dict)
        self.future_bindings: dict[SymbolId | None, dict[str, SymbolId]] = defaultdict(dict)
        self.types: dict[SymbolId | None, dict[str, SymbolId]] = defaultdict(dict)
        self.local_names: dict[SymbolId, set[str]] = defaultdict(set)
        self.global_names: dict[SymbolId, set[str]] = defaultdict(set)
        self.nonlocal_names: dict[SymbolId, set[str]] = defaultdict(set)
        self._type_checking_depth = 0
        self._type_resolution_depth = 0
        self._locations: dict[ast.AST, SourceRange] = {}
        self._provenances: dict[ast.AST, Provenance] = {}
        self._written_names: dict[ast.AST, str] = {}
        self._resolutions: dict[ast.AST, SymbolRef] = {}
        self.node_scopes: dict[ast.AST, SymbolId] = {}
        self.variable_symbols: set[SymbolId] = set()
        self.context_manager_providers: dict[SymbolId, SymbolId] = {}

    def _prime_statements(self, statements: list[ast.stmt], scope: SymbolId | None) -> None:
        """Plan lexical scopes without making executable bindings visible early."""
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                symbol = self._child_symbol(scope, statement.name)
                self.node_scopes[statement] = symbol
                self.scopes[symbol] = Scope(
                    symbol,
                    scope,
                    "class" if isinstance(statement, ast.ClassDef) else "function",
                )
                if scope is None:
                    self.future_bindings[scope][statement.name] = symbol
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    outer_expressions: list[ast.AST] = [
                        *statement.decorator_list,
                        *statement.args.defaults,
                        *(item for item in statement.args.kw_defaults if item),
                        *(
                            argument.annotation
                            for argument in (
                                *statement.args.posonlyargs,
                                *statement.args.args,
                                *statement.args.kwonlyargs,
                            )
                            if argument.annotation is not None
                        ),
                    ]
                    if statement.returns is not None:
                        outer_expressions.append(statement.returns)
                    self._prime_scope_nodes(outer_expressions, scope)
                    self._plan_function_names(statement, symbol)
                    self.local_names[symbol].update(
                        argument.arg
                        for argument in (
                            *statement.args.posonlyargs,
                            *statement.args.args,
                            *statement.args.kwonlyargs,
                        )
                    )
                    if statement.args.vararg is not None:
                        self.local_names[symbol].add(statement.args.vararg.arg)
                    if statement.args.kwarg is not None:
                        self.local_names[symbol].add(statement.args.kwarg.arg)
                else:
                    self._prime_scope_nodes([*statement.decorator_list, *statement.bases], scope)
                self._prime_scope_nodes(statement.body, symbol)
            elif isinstance(statement, ast.Import):
                if scope is None:
                    for alias in statement.names:
                        self.future_bindings[scope][alias.asname or alias.name.split(".")[0]] = (
                            SymbolId(alias.name if alias.asname else alias.name.split(".")[0])
                        )
            elif isinstance(statement, ast.ImportFrom):
                if scope is None:
                    base = self._absolute_import_base(statement.module, statement.level)
                    for alias in statement.names:
                        if alias.name != "*":
                            self.future_bindings[scope][alias.asname or alias.name] = SymbolId(
                                f"{base}.{alias.name}" if base else alias.name
                            )
            else:
                if scope is None:
                    future_statement = statement
                    if isinstance(statement, ast.If) and self._is_type_checking_test(
                        statement.test
                    ):
                        future_statement = ast.If(
                            test=statement.test,
                            body=statement.orelse,
                            orelse=[],
                        )
                    for name in self._statement_assigned_names(future_statement):
                        self.future_bindings[None][name] = self._child_symbol(None, name)
                self._prime_scope_nodes([statement], scope)

    def _is_type_checking_test(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Name):
            return self.future_bindings[None].get(node.id) == SymbolId("typing.TYPE_CHECKING")
        return (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "typing"
            and node.attr == "TYPE_CHECKING"
        )

    def _plan_function_names(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, scope: SymbolId
    ) -> None:
        globals_: set[str] = set()
        nonlocals: set[str] = set()
        for statement in node.body:
            for child in self._same_scope_nodes(statement):
                if isinstance(child, ast.Global):
                    globals_.update(child.names)
                elif isinstance(child, ast.Nonlocal):
                    nonlocals.update(child.names)
        self.global_names[scope].update(globals_)
        self.nonlocal_names[scope].update(nonlocals)
        for statement in node.body:
            self.local_names[scope].update(self._statement_assigned_names(statement))
        self.local_names[scope].difference_update(globals_ | nonlocals)

    def _same_scope_nodes(self, node: ast.AST) -> list[ast.AST]:
        result = [node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return result
        for child in ast.iter_child_nodes(node):
            result.extend(self._same_scope_nodes(child))
        return result

    def _statement_assigned_names(self, statement: ast.stmt) -> set[str]:
        names: set[str] = set()
        for node in self._same_scope_nodes(statement):
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                names.add(node.id)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
            elif isinstance(node, ast.Import):
                names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                names.update(
                    alias.asname or alias.name for alias in node.names if alias.name != "*"
                )
        return names

    def _prime_scope_nodes(self, nodes: Sequence[ast.AST], scope: SymbolId | None) -> None:
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node not in self.node_scopes:
                    self._prime_statements([node], scope)
                continue
            if isinstance(node, ast.Lambda):
                self._prime_scope_nodes(
                    [*node.args.defaults, *(item for item in node.args.kw_defaults if item)], scope
                )
                symbol = self._synthetic_symbol(scope, "lambda", node)
                self.node_scopes[node] = symbol
                self.scopes[symbol] = Scope(symbol, scope, "function")
                arguments = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
                self.local_names[symbol].update(argument.arg for argument in arguments)
                if node.args.vararg:
                    self.local_names[symbol].add(node.args.vararg.arg)
                if node.args.kwarg:
                    self.local_names[symbol].add(node.args.kwarg.arg)
                self._prime_scope_nodes([node.body], symbol)
                continue
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                first, *rest = node.generators
                self._prime_scope_nodes([first.iter], scope)
                symbol = self._synthetic_symbol(scope, "comprehension", node)
                self.node_scopes[node] = symbol
                self.scopes[symbol] = Scope(symbol, scope, "comprehension")
                for generator in node.generators:
                    self.local_names[symbol].update(
                        child.id
                        for child in ast.walk(generator.target)
                        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)
                    )
                scoped_nodes: list[ast.AST] = [first.target, *first.ifs]
                for generator in rest:
                    scoped_nodes.extend([generator.iter, generator.target, *generator.ifs])
                if isinstance(node, ast.DictComp):
                    scoped_nodes.extend([node.key, node.value])
                else:
                    scoped_nodes.append(node.elt)
                self._prime_scope_nodes(scoped_nodes, symbol)
                continue
            self._prime_scope_nodes(list(ast.iter_child_nodes(node)), scope)

    def _synthetic_symbol(self, scope: SymbolId | None, kind: str, node: ast.expr) -> SymbolId:
        parent = scope.value if scope else self.source.module_id.value
        return SymbolId(f"{parent}.__{kind}_{node.lineno}_{node.col_offset}")

    def _child_symbol(self, scope: SymbolId | None, name: str) -> SymbolId:
        return SymbolId(f"{scope.value if scope else self.source.module_id.value}.{name}")

    def _location(self, node: ast.AST) -> SourceRange:
        if node not in self._locations:
            self._locations[node] = node_range(self.source, node)
        return self._locations[node]

    def _provenance(self, node: ast.AST) -> Provenance:
        if node not in self._provenances:
            self._provenances[node] = Provenance(
                PYTHON_AST_IDENTITY.name,
                PYTHON_AST_IDENTITY.version,
                self.source.content_hash,
                self._location(node),
            )
        return self._provenances[node]

    def _written_name(self, node: ast.AST) -> str:
        if node not in self._written_names:
            self._written_names[node] = written_name(node)
        return self._written_names[node]

    def _absolute_import_base(self, module: str | None, level: int) -> str:
        return absolute_import_base(self.source.module_id, self.source.is_package, module, level)

    def _scope_chain(self) -> list[SymbolId | None]:
        result: list[SymbolId | None] = []
        scope = self.current_scope
        while True:
            result.append(scope)
            if scope is None:
                return result
            parent = self.scopes[scope].parent
            if self.scopes[scope].kind in {"function", "comprehension"}:
                while parent is not None and self.scopes[parent].kind == "class":
                    parent = self.scopes[parent].parent
            scope = parent

    def _lookup(self, name: str, *, type_only: bool = False) -> SymbolId | None:
        table = self.types if type_only else self.bindings
        if (
            self.current_scope in self.global_names
            and name in self.global_names[self.current_scope]
        ):
            return table[None].get(name)
        if (
            self.current_scope in self.nonlocal_names
            and name in self.nonlocal_names[self.current_scope]
        ):
            scope = self.scopes[self.current_scope].parent
            while scope is not None:
                if scope in self.local_names and name in self.local_names[scope]:
                    return table[scope].get(name)
                scope = self.scopes[scope].parent
        if self.current_scope in self.local_names and name in self.local_names[self.current_scope]:
            return table[self.current_scope].get(name)
        for scope in self._scope_chain():
            if (value := table[scope].get(name)) is not None:
                return value
            if (
                scope is None
                and self.current_scope is not None
                and not type_only
                and (value := self.future_bindings[None].get(name)) is not None
            ):
                return value
        return None

    def _lookup_binding_state(self, name: str) -> BindingState | None:
        if self._type_resolution_depth:
            for scope in self._scope_chain():
                if (symbol := self.type_bindings[scope].get(name)) is not None:
                    return BindingState(frozenset({symbol}), True, frozenset())
        if (
            self.current_scope in self.global_names
            and name in self.global_names[self.current_scope]
        ):
            return self.binding_states[None].get(name) or self._future_binding_state(name)
        if (
            self.current_scope in self.nonlocal_names
            and name in self.nonlocal_names[self.current_scope]
        ):
            scope = self.scopes[self.current_scope].parent
            while scope is not None:
                if scope in self.local_names and name in self.local_names[scope]:
                    return self.binding_states[scope].get(name)
                scope = self.scopes[scope].parent
        if self.current_scope in self.local_names and name in self.local_names[self.current_scope]:
            return self.binding_states[self.current_scope].get(name)
        for scope in self._scope_chain():
            if (state := self.binding_states[scope].get(name)) is not None:
                return state
            if (
                scope is None
                and self.current_scope is not None
                and (state := self._future_binding_state(name)) is not None
            ):
                return state
        return None

    def _future_binding_state(self, name: str) -> BindingState | None:
        symbol = self.future_bindings[None].get(name)
        return BindingState(frozenset({symbol}), True, frozenset()) if symbol is not None else None

    def _declare(self, name: str, symbol: SymbolId, binding_id: FactId | None = None) -> None:
        scope = self._binding_scope(name)
        if self._type_checking_depth:
            self.type_bindings[scope][name] = symbol
            return
        self.bindings[scope][name] = symbol
        self.binding_states[scope][name] = BindingState(
            frozenset({symbol}), True, frozenset({binding_id}) if binding_id else frozenset()
        )

    def _declare_assignment(self, name: str, binding_id: FactId | None = None) -> None:
        scope = self._binding_scope(name)
        symbol = self._child_symbol(scope, name)
        self.variable_symbols.add(symbol)
        self.bindings[scope][name] = symbol
        self.binding_states[scope][name] = BindingState(
            frozenset({symbol}), True, frozenset({binding_id}) if binding_id else frozenset()
        )

    def _binding_scope(self, name: str) -> SymbolId | None:
        scope = self.current_scope
        if scope in self.global_names and name in self.global_names[scope]:
            scope = None
        elif scope in self.nonlocal_names and name in self.nonlocal_names[scope]:
            scope = self.scopes[scope].parent
            while scope is not None and (
                self.scopes[scope].kind == "class" or name not in self.local_names.get(scope, set())
            ):
                scope = self.scopes[scope].parent
        return scope

    def _is_deferred_scope(self) -> bool:
        scope = self.current_scope
        while scope is not None:
            if scope in self.local_names:
                return True
            scope = self.scopes[scope].parent
        return False

    def _resolve(self, node: ast.AST) -> SymbolRef:
        if node not in self._resolutions:
            self._resolutions[node] = self._resolve_uncached(node)
        return self._resolutions[node]

    def _next_fact_id(self, kind: FactKind, subject: str) -> FactId:
        return next_fact_id(
            self.source.module_id.value, self.current_scope, kind, subject, self.occurrences
        )

    def _resolved_binding_ids(self, node: ast.AST) -> tuple[FactId, ...]:
        state = self._lookup_binding_state(node.id) if isinstance(node, ast.Name) else None
        return tuple(sorted(state.binding_ids, key=lambda item: item.value)) if state else ()

    def _resolve_uncached(self, node: ast.AST) -> SymbolRef:
        name = self._written_name(node)
        provenance = self._provenance(node)
        if isinstance(node, ast.Name):
            binding = self._lookup_binding_state(node.id)
            if binding is not None:
                candidates = tuple(sorted(binding.candidates, key=lambda item: item.value))
                if len(candidates) > 1:
                    return SymbolRef(name, ResolutionState.AMBIGUOUS, None, candidates, provenance)
                if candidates and not binding.definite:
                    return SymbolRef(
                        name, ResolutionState.CONDITIONAL, None, candidates, provenance
                    )
                if candidates:
                    return SymbolRef(name, ResolutionState.RESOLVED, candidates[0], (), provenance)
            symbol = SymbolId(f"builtins.{node.id}") if node.id in _BUILTINS else None
            state = ResolutionState.RESOLVED if symbol is not None else ResolutionState.UNRESOLVED
            return SymbolRef(name, state, symbol, (), provenance)
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                typed = self._lookup(node.value.id, type_only=True)
                if typed is not None:
                    return SymbolRef(
                        name,
                        ResolutionState.RESOLVED,
                        SymbolId(f"{typed.value}.{node.attr}"),
                        (),
                        provenance,
                    )
            base = self._resolve(node.value)
            if base.state is ResolutionState.RESOLVED and base.symbol:
                if base.symbol in self.variable_symbols:
                    return SymbolRef(name, ResolutionState.UNRESOLVED, None, (), provenance)
                return SymbolRef(
                    name,
                    ResolutionState.RESOLVED,
                    SymbolId(f"{base.symbol.value}.{node.attr}"),
                    (),
                    provenance,
                )
            candidates = tuple(
                SymbolId(f"{candidate.value}.{node.attr}") for candidate in base.candidates
            )
            return SymbolRef(name, base.state, None, candidates, provenance)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
        ):
            return SymbolRef(name, ResolutionState.DYNAMIC, None, (), provenance)
        return SymbolRef(name, ResolutionState.DYNAMIC, None, (), provenance)

    def _annotation_symbol(self, node: ast.expr | None) -> SymbolId | None:
        self._enter_type_resolution()
        ref = self._resolve(node) if node is not None else None
        self._leave_type_resolution()
        return ref.symbol if ref and ref.state is ResolutionState.RESOLVED else None

    def _context_manager_item_type(self, expression: ast.expr) -> SymbolId | None:
        if not isinstance(expression, ast.Call):
            return None
        provider = self._resolve(expression.func)
        if provider.state is not ResolutionState.RESOLVED or provider.symbol is None:
            return None
        return self.context_manager_providers.get(provider.symbol)
