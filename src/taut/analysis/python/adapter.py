from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import replace

from taut.analysis.contracts import (
    ResolverSettings,
    SourceInput,
)
from taut.analysis.python.binding_forms import PythonBindingFormsMixin
from taut.analysis.python.control_flow import PythonControlFlowVisitor
from taut.analysis.python.expression_summary import (
    ExpressionSummarizer,
)
from taut.analysis.python.fact_order import fact_sort_key
from taut.analysis.python.import_intent import optional_import_nodes
from taut.analysis.python.module_relations import emit_module_relations
from taut.analysis.python.return_summaries import (
    resolved_return_symbols,
    returned_mapping_keys,
)
from taut.analysis.python.scope_flow import BindingState
from taut.analysis.python.symbol_resolver import (
    PythonSymbolResolver,
)
from taut.analysis.python.syntax_context import SyntaxContextStack
from taut.domain.facts import (
    AnalysisStage,
    BindingFact,
    CallFact,
    ClassFact,
    CompletenessState,
    DecoratorFact,
    DefinitionFact,
    ExecutionPhase,
    ExpressionSummary,
    FactKind,
    FieldFact,
    FunctionFact,
    ImportFact,
    ImportIntent,
    ModuleCompleteness,
    ModuleFacts,
    ModuleIdentity,
    ReferenceFact,
    ScopeKind,
    SymbolRef,
    SyntaxContext,
    SyntaxPosition,
)
from taut.domain.frozen import FrozenMap
from taut.domain.ids import FactId, SymbolId
from taut.domain.relations import BindingKind, ModuleRelations

_ALL_FACTS = frozenset(FactKind)


class PythonFactExtractor(PythonBindingFormsMixin, PythonControlFlowVisitor):
    def __init__(self, source: SourceInput, resolver: ResolverSettings) -> None:
        PythonSymbolResolver.__init__(self, source)
        self.context_manager_providers = {
            provider.symbol: provider.item_type for provider in resolver.context_manager_providers
        }
        self.occurrences: dict[tuple[str, str, str], int] = defaultdict(int)
        self.imports: list[ImportFact] = []
        self.definitions: list[DefinitionFact] = []
        self.references: list[ReferenceFact] = []
        self.calls: list[CallFact] = []
        self.decorators: list[DecoratorFact] = []
        self.functions: list[FunctionFact] = []
        self.classes: list[ClassFact] = []
        self.fields: list[FieldFact] = []
        self.binding_facts: list[BindingFact] = []
        self._reference_binding_ids: dict[FactId, FactId | None] = {}
        self._reference_candidate_binding_ids: dict[FactId, tuple[FactId, ...]] = {}
        self._binding_kind = BindingKind.ASSIGNMENT
        self._binding_targets: dict[ast.AST, BindingKind] = {}
        self._optional_import_nodes: set[ast.Import | ast.ImportFrom] = set()
        self.class_symbols: set[SymbolId] = set()
        self.function_symbols: set[SymbolId] = set()
        self._function_nodes: dict[SymbolId, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self._deferred_bodies: list[tuple[SymbolId, list[ast.stmt]]] = []
        self.enclosing_contexts: list[SymbolRef] = []
        self._syntax = SyntaxContextStack()
        self._summarizer = ExpressionSummarizer(self._resolve, self._written_name, self._location)

    def _syntax_context(self) -> SyntaxContext:
        scope_kind = (
            ScopeKind.CLASS
            if self.current_scope in self.class_symbols
            else ScopeKind.FUNCTION
            if self.current_scope in self.function_symbols
            else ScopeKind.MODULE
        )
        return self._syntax.current(
            self.current_scope,
            scope_kind,
            (ExecutionPhase.DEFERRED if self._is_deferred_scope() else ExecutionPhase.MODULE_INIT),
        )

    def extract(self, tree: ast.Module) -> ModuleFacts:
        self._prime_statements(tree.body, None)
        self._index_binding_targets(tree)  # type: ignore[misc]
        self._optional_import_nodes = optional_import_nodes(tree)
        self.visit(tree)
        deferred_index = 0
        while deferred_index < len(self._deferred_bodies):
            scope, body = self._deferred_bodies[deferred_index]
            deferred_index += 1
            previous = self.current_scope
            self.current_scope = scope
            for statement in body:
                self.visit(statement)
            self.current_scope = previous
        previous_scope = self.current_scope
        resolved_functions: list[FunctionFact] = []
        for function in self.functions:
            node = self._function_nodes[function.symbol_id]
            self.current_scope = function.symbol_id
            resolved_functions.append(
                replace(
                    function,
                    returned_symbols=resolved_return_symbols(
                        node, self._resolve, self._written_name, self._location
                    ),
                )
            )
        self.functions = resolved_functions
        self.current_scope = previous_scope
        module = ModuleIdentity(
            id=self.source.module_id,
            path=self.source.path,
            kind=self.source.kind,
            is_policy_target=self.source.is_policy_target,
            is_package=self.source.is_package,
            line_count=len(self.source.content.splitlines()),
        )
        completeness = ModuleCompleteness(
            state=CompletenessState.COMPLETE,
            stage=AnalysisStage.FACTS_READY,
            available_facts=_ALL_FACTS,
            unavailable_facts=FrozenMap(),
        )
        facts = ModuleFacts(
            module=module,
            imports=tuple(sorted(self.imports, key=fact_sort_key)),
            definitions=tuple(sorted(self.definitions, key=fact_sort_key)),
            references=tuple(sorted(self.references, key=fact_sort_key)),
            calls=tuple(sorted(self.calls, key=fact_sort_key)),
            decorators=tuple(sorted(self.decorators, key=fact_sort_key)),
            functions=tuple(sorted(self.functions, key=fact_sort_key)),
            classes=tuple(sorted(self.classes, key=fact_sort_key)),
            fields=tuple(sorted(self.fields, key=fact_sort_key)),
            bindings=tuple(
                sorted(
                    self.binding_facts,
                    key=lambda item: (
                        item.location.start_line,
                        item.location.start_column,
                        item.id.value,
                    ),
                )
            ),
            completeness=completeness,
        )
        return facts

    def relations(self, facts: ModuleFacts) -> ModuleRelations:
        return emit_module_relations(
            facts, self._reference_binding_ids, self._reference_candidate_binding_ids
        )

    def _expression_summary(self, node: ast.AST) -> ExpressionSummary:
        return self._summarizer.expression(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local_name = alias.asname or alias.name.split(".", 1)[0]
            target = alias.name if alias.asname else alias.name.split(".", 1)[0]
            normalized = f"import:{alias.name}:{alias.asname or ''}"
            fact_id = self._next_fact_id(FactKind.IMPORT, normalized)
            self._declare(local_name, SymbolId(target), fact_id)
            self.imports.append(
                ImportFact(
                    id=fact_id,
                    module_id=self.source.module_id,
                    imported_name=alias.name,
                    imported_module_name=alias.name,
                    alias=alias.asname,
                    is_from=False,
                    relative_level=0,
                    enclosing_symbol=self.current_scope,
                    location=self._location(node),
                    provenance=self._provenance(node),
                    context=self._syntax_context(),
                    intent=(
                        ImportIntent.OPTIONAL_DEPENDENCY
                        if node in self._optional_import_nodes
                        else ImportIntent.NORMAL
                    ),
                )
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        base = self._absolute_import_base(node.module, node.level)
        for alias in node.names:
            imported_name = f"{base}.{alias.name}" if base and alias.name != "*" else base
            normalized = f"from:{imported_name}:{alias.asname or ''}"
            fact_id = self._next_fact_id(FactKind.IMPORT, normalized)
            if alias.name != "*":
                self._declare(
                    alias.asname or alias.name,
                    SymbolId(f"{base}.{alias.name}" if base else alias.name),
                    fact_id,
                )
            self.imports.append(
                ImportFact(
                    id=fact_id,
                    module_id=self.source.module_id,
                    imported_name=imported_name,
                    imported_module_name=base,
                    alias=alias.asname,
                    is_from=True,
                    relative_level=node.level,
                    enclosing_symbol=self.current_scope,
                    location=self._location(node),
                    provenance=self._provenance(node),
                    context=self._syntax_context(),
                    intent=(
                        ImportIntent.OPTIONAL_DEPENDENCY
                        if node in self._optional_import_nodes
                        else ImportIntent.NORMAL
                    ),
                )
            )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        symbol = self.node_scopes[node]
        definition_id = self._next_fact_id(FactKind.DEFINITION, f"class:{symbol.value}")
        self._declare(node.name, symbol, definition_id)
        self.class_symbols.add(symbol)
        self.definitions.append(
            DefinitionFact(
                id=definition_id,
                module_id=self.source.module_id,
                symbol_id=symbol,
                kind="class",
                enclosing_symbol=self.current_scope,
                location=self._location(node),
                provenance=self._provenance(node),
                context=self._syntax_context(),
            )
        )
        self.classes.append(
            ClassFact(
                id=self._next_fact_id(FactKind.CLASS, symbol.value),
                module_id=self.source.module_id,
                symbol_id=symbol,
                name=node.name,
                bases=tuple(self._expression_summary(base) for base in node.bases),
                has_docstring=ast.get_docstring(node, clean=False) is not None,
                location=self._location(node),
                provenance=self._provenance(node),
                context=self._syntax_context(),
            )
        )
        for decorator in node.decorator_list:
            self._add_decorator(symbol, decorator)
        with self._syntax.occurrence(position=SyntaxPosition.BASE):
            for base in node.bases:
                self.visit(base)
        previous = self.current_scope
        self.current_scope = symbol
        for statement in node.body:
            self.visit(statement)
        self.current_scope = previous

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool) -> None:
        symbol = self.node_scopes[node]
        definition_id = self._next_fact_id(FactKind.DEFINITION, f"function:{symbol.value}")
        self._declare(node.name, symbol, definition_id)
        self.function_symbols.add(symbol)
        self._function_nodes[symbol] = node
        decorator_refs = tuple(self._resolve(decorator) for decorator in node.decorator_list)
        self._enter_type_resolution()
        parameters = self._summarizer.parameters(node)
        return_annotation = (
            self._expression_summary(node.returns) if node.returns is not None else None
        )
        self._leave_type_resolution()
        self.definitions.append(
            DefinitionFact(
                id=definition_id,
                module_id=self.source.module_id,
                symbol_id=symbol,
                kind="function",
                enclosing_symbol=self.current_scope,
                location=self._location(node),
                provenance=self._provenance(node),
                context=self._syntax_context(),
            )
        )
        self.functions.append(
            FunctionFact(
                id=self._next_fact_id(FactKind.FUNCTION, symbol.value),
                module_id=self.source.module_id,
                symbol_id=symbol,
                name=node.name,
                is_async=is_async,
                decorators=decorator_refs,
                parameters=parameters,
                return_annotation=return_annotation,
                has_docstring=ast.get_docstring(node, clean=False) is not None,
                location=self._location(node),
                provenance=self._provenance(node),
                context=self._syntax_context(),
                returned_mapping_keys=returned_mapping_keys(node),
            )
        )
        for decorator in node.decorator_list:
            self._add_decorator(symbol, decorator)
        defaults = (*node.args.defaults, *(item for item in node.args.kw_defaults if item))
        with self._syntax.occurrence(position=SyntaxPosition.DEFAULT):
            for default in defaults:
                self.visit(default)
        arguments = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
        if node.args.vararg is not None:
            arguments += (node.args.vararg,)
        if node.args.kwarg is not None:
            arguments += (node.args.kwarg,)
        for argument in arguments:
            parameter_symbol = self._child_symbol(symbol, argument.arg)
            self._prepare_flow_write(symbol)
            self.bindings[symbol][argument.arg] = parameter_symbol
            parameter_id = self._next_fact_id(
                FactKind.FIELD, f"parameter:{symbol.value}:{argument.arg}"
            )
            self.binding_states[symbol][argument.arg] = BindingState(
                frozenset({parameter_symbol}), True, frozenset({parameter_id})
            )
            self.binding_facts.append(
                BindingFact(
                    id=parameter_id,
                    module_id=self.source.module_id,
                    local_name=argument.arg,
                    kind=BindingKind.PARAMETER,
                    lexical_owner=symbol,
                    symbol_id=parameter_symbol,
                    location=self._location(argument),
                    provenance=self._provenance(argument),
                    context=replace(
                        self._syntax_context(), lexical_owner=symbol, scope_kind=ScopeKind.FUNCTION
                    ),
                )
            )
            annotation = self._annotation_symbol(argument.annotation)
            if annotation is not None:
                self.types[symbol][argument.arg] = annotation
            if argument.annotation is not None:
                with self._syntax.occurrence(position=SyntaxPosition.ANNOTATION):
                    self._enter_type_resolution()
                    self.visit(argument.annotation)
                    self._leave_type_resolution()
        if node.returns is not None:
            with self._syntax.occurrence(position=SyntaxPosition.ANNOTATION):
                self._enter_type_resolution()
                self.visit(node.returns)
                self._leave_type_resolution()
        self._deferred_bodies.append((symbol, node.body))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node, False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node, True)

    def _add_decorator(self, symbol: SymbolId, node: ast.expr) -> None:
        ref = self._resolve(node.func if isinstance(node, ast.Call) else node)
        fact_id = self._next_fact_id(FactKind.DECORATOR, f"{symbol.value}:{ref.written_name}")
        self.decorators.append(
            DecoratorFact(
                id=fact_id,
                module_id=self.source.module_id,
                decorated_symbol=symbol,
                ref=ref,
                arguments=(self._summarizer.arguments(node) if isinstance(node, ast.Call) else ()),
                location=self._location(node),
                provenance=self._provenance(node),
                context=self._syntax_context(),
            )
        )
        with self._syntax.occurrence(position=SyntaxPosition.DECORATOR, parent=fact_id):
            self.visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        ref = self._resolve(node.func)
        fact_id = self._next_fact_id(
            FactKind.CALL, ref.symbol.value if ref.symbol else ref.written_name
        )
        self.calls.append(
            CallFact(
                id=fact_id,
                module_id=self.source.module_id,
                ref=ref,
                enclosing_symbol=self.current_scope,
                positional_argument_count=len(node.args),
                keyword_names=tuple(
                    sorted(keyword.arg for keyword in node.keywords if keyword.arg is not None)
                ),
                has_keyword_unpack=any(keyword.arg is None for keyword in node.keywords),
                arguments=self._summarizer.arguments(node),
                enclosing_contexts=tuple(self.enclosing_contexts),
                location=self._location(node),
                provenance=self._provenance(node),
                context=self._syntax_context(),
            )
        )
        with self._syntax.occurrence(parent=fact_id):
            self.visit(node.func)
        position = 0
        for argument in node.args:
            with self._syntax.occurrence(
                position=SyntaxPosition.ARGUMENT,
                parent=fact_id,
                argument_position=position,
            ):
                self.visit(argument)
            position += 1
        for keyword in node.keywords:
            with self._syntax.occurrence(
                position=SyntaxPosition.ARGUMENT,
                parent=fact_id,
                argument_name=keyword.arg,
                argument_position=position,
            ):
                self.visit(keyword.value)
            position += 1

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.ctx, ast.Load):
            ref = self._resolve(node)
            self.references.append(
                ReferenceFact(
                    id=self._next_fact_id(
                        FactKind.REFERENCE,
                        ref.symbol.value if ref.symbol else ref.written_name,
                    ),
                    module_id=self.source.module_id,
                    ref=ref,
                    enclosing_symbol=self.current_scope,
                    location=self._location(node),
                    provenance=self._provenance(node),
                    context=self._syntax_context(),
                )
            )
        self.generic_visit(node)

    def _visit_with(self, node: ast.With | ast.AsyncWith) -> None:
        pushed_contexts = 0
        for item in node.items:
            with self._syntax.occurrence(position=SyntaxPosition.CONTEXT_MANAGER):
                self.visit(item.context_expr)
            if isinstance(item.context_expr, ast.Call):
                self.enclosing_contexts.append(self._resolve(item.context_expr.func))
                pushed_contexts += 1
            if item.optional_vars is None:
                continue
            item_type = self._context_manager_item_type(item.context_expr)
            if item_type is not None and isinstance(item.optional_vars, ast.Name):
                self.types[self.current_scope][item.optional_vars.id] = item_type
            self.visit(item.optional_vars)
        for statement in node.body:
            self.visit(statement)
        if pushed_contexts:
            del self.enclosing_contexts[-pushed_contexts:]

    def visit_With(self, node: ast.With) -> None:
        self._visit_with(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._visit_with(node)
