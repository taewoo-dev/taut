from __future__ import annotations

import ast
import hashlib
from collections import defaultdict

from taut.analysis.contracts import (
    ResolverSettings,
    SourceInput,
)
from taut.analysis.python.expression_summary import (
    ExpressionSummarizer,
)
from taut.analysis.python.fact_order import fact_sort_key
from taut.analysis.python.symbol_resolver import (
    PythonSymbolResolver,
)
from taut.analysis.python.syntax_context import SyntaxContextStack
from taut.domain.facts import (
    AnalysisStage,
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
    GuardKind,
    ImportFact,
    ModuleCompleteness,
    ModuleFacts,
    ModuleIdentity,
    ReferenceFact,
    ResolutionState,
    ScopeKind,
    SymbolRef,
    SyntaxContext,
    SyntaxPosition,
)
from taut.domain.frozen import FrozenMap
from taut.domain.ids import FactId, SymbolId

_ALL_FACTS = frozenset(FactKind)


class PythonFactExtractor(PythonSymbolResolver, ast.NodeVisitor):
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
        self.class_symbols: set[SymbolId] = set()
        self.function_symbols: set[SymbolId] = set()
        self.enclosing_contexts: list[SymbolRef] = []
        self._syntax = SyntaxContextStack()
        self._summarizer = ExpressionSummarizer(self._resolve, self._written_name)

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
        self.visit(tree)
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
        return ModuleFacts(
            module=module,
            imports=tuple(sorted(self.imports, key=fact_sort_key)),
            definitions=tuple(sorted(self.definitions, key=fact_sort_key)),
            references=tuple(sorted(self.references, key=fact_sort_key)),
            calls=tuple(sorted(self.calls, key=fact_sort_key)),
            decorators=tuple(sorted(self.decorators, key=fact_sort_key)),
            functions=tuple(sorted(self.functions, key=fact_sort_key)),
            classes=tuple(sorted(self.classes, key=fact_sort_key)),
            fields=tuple(sorted(self.fields, key=fact_sort_key)),
            completeness=completeness,
        )

    def _fact_id(self, kind: FactKind, normalized_subject: str) -> FactId:
        scope = self.current_scope.value if self.current_scope else self.source.module_id.value
        key = (scope, kind.value, normalized_subject)
        occurrence = self.occurrences[key]
        self.occurrences[key] += 1
        raw = "\0".join(
            (self.source.module_id.value, scope, kind.value, normalized_subject, str(occurrence))
        )
        return FactId(hashlib.sha256(raw.encode()).hexdigest())

    def _expression_summary(self, node: ast.AST) -> ExpressionSummary:
        return self._summarizer.expression(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local_name = alias.asname or alias.name.split(".", 1)[0]
            target = alias.name if alias.asname else alias.name.split(".", 1)[0]
            self._declare(local_name, SymbolId(target))
            normalized = f"import:{alias.name}:{alias.asname or ''}"
            self.imports.append(
                ImportFact(
                    id=self._fact_id(FactKind.IMPORT, normalized),
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
                )
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        base = self._absolute_import_base(node.module, node.level)
        for alias in node.names:
            if alias.name != "*":
                self._declare(
                    alias.asname or alias.name,
                    SymbolId(f"{base}.{alias.name}" if base else alias.name),
                )
            imported_name = f"{base}.{alias.name}" if base and alias.name != "*" else base
            normalized = f"from:{imported_name}:{alias.asname or ''}"
            self.imports.append(
                ImportFact(
                    id=self._fact_id(FactKind.IMPORT, normalized),
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
                )
            )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        symbol = self._child_symbol(self.current_scope, node.name)
        self._declare(node.name, symbol)
        self.class_symbols.add(symbol)
        self.definitions.append(
            DefinitionFact(
                id=self._fact_id(FactKind.DEFINITION, f"class:{symbol.value}"),
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
                id=self._fact_id(FactKind.CLASS, symbol.value),
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
        symbol = self._child_symbol(self.current_scope, node.name)
        self._declare(node.name, symbol)
        self.function_symbols.add(symbol)
        decorator_refs = tuple(self._resolve(decorator) for decorator in node.decorator_list)
        self.definitions.append(
            DefinitionFact(
                id=self._fact_id(FactKind.DEFINITION, f"function:{symbol.value}"),
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
                id=self._fact_id(FactKind.FUNCTION, symbol.value),
                module_id=self.source.module_id,
                symbol_id=symbol,
                name=node.name,
                is_async=is_async,
                decorators=decorator_refs,
                parameters=self._summarizer.parameters(node),
                return_annotation=(
                    self._expression_summary(node.returns) if node.returns is not None else None
                ),
                has_docstring=ast.get_docstring(node, clean=False) is not None,
                location=self._location(node),
                provenance=self._provenance(node),
                context=self._syntax_context(),
            )
        )
        for decorator in node.decorator_list:
            self._add_decorator(symbol, decorator)
        defaults = (*node.args.defaults, *(item for item in node.args.kw_defaults if item))
        with self._syntax.occurrence(position=SyntaxPosition.DEFAULT):
            for default in defaults:
                self.visit(default)
        arguments = (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        )
        if node.args.vararg is not None:
            arguments += (node.args.vararg,)
        if node.args.kwarg is not None:
            arguments += (node.args.kwarg,)
        for argument in arguments:
            annotation = self._annotation_symbol(argument.annotation)
            if annotation is not None:
                self.types[symbol][argument.arg] = annotation
            if argument.annotation is not None:
                with self._syntax.occurrence(position=SyntaxPosition.ANNOTATION):
                    self.visit(argument.annotation)
        if node.returns is not None:
            with self._syntax.occurrence(position=SyntaxPosition.ANNOTATION):
                self.visit(node.returns)
        previous = self.current_scope
        self.current_scope = symbol
        for statement in node.body:
            self.visit(statement)
        self.current_scope = previous

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node, False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node, True)

    def _add_decorator(self, symbol: SymbolId, node: ast.expr) -> None:
        ref = self._resolve(node.func if isinstance(node, ast.Call) else node)
        fact_id = self._fact_id(FactKind.DECORATOR, f"{symbol.value}:{ref.written_name}")
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
        ref = self._contextual_ref(self._resolve(node.func), self._syntax_context().guard)
        fact_id = self._fact_id(FactKind.CALL, ref.symbol.value if ref.symbol else ref.written_name)
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

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            ref = self._contextual_ref(self._resolve(node), self._syntax_context().guard)
            self.references.append(
                ReferenceFact(
                    id=self._fact_id(
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

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.ctx, ast.Load):
            ref = self._contextual_ref(self._resolve(node), self._syntax_context().guard)
            self.references.append(
                ReferenceFact(
                    id=self._fact_id(
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

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        test_ref = self._resolve(node.test)
        is_type_checking = (
            test_ref.state is ResolutionState.RESOLVED
            and test_ref.symbol is not None
            and test_ref.symbol.value == "typing.TYPE_CHECKING"
        )
        body_guard = GuardKind.TYPE_CHECKING_ONLY if is_type_checking else GuardKind.CONDITIONAL
        with self._syntax.occurrence(guard=body_guard):
            for statement in node.body:
                self.visit(statement)
        if node.orelse:
            with self._syntax.occurrence(guard=GuardKind.CONDITIONAL):
                for statement in node.orelse:
                    self.visit(statement)
        self._mark_conditional_branch((*node.body, *node.orelse))

    def _context_manager_item_type(self, expression: ast.expr) -> SymbolId | None:
        if not isinstance(expression, ast.Call):
            return None
        provider = self._resolve(expression.func)
        if provider.state is not ResolutionState.RESOLVED or provider.symbol is None:
            return None
        return self.context_manager_providers.get(provider.symbol)

    def visit_With(self, node: ast.With) -> None:
        self._visit_with(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._visit_with(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name):
            annotation = self._annotation_symbol(node.annotation)
            if annotation is not None:
                self.types[self.current_scope][node.target.id] = annotation
            self._add_field(
                node.target.id,
                node,
                self._expression_summary(node.annotation),
                self._expression_summary(node.value) if node.value is not None else None,
                True,
            )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._add_field(
                    target.id,
                    node,
                    None,
                    self._expression_summary(node.value),
                    False,
                )
        self.visit(node.value)
        inferred: SymbolId | None = None
        if isinstance(node.value, ast.Call):
            ref = self._resolve(node.value.func)
            if ref.state is ResolutionState.RESOLVED:
                inferred = ref.symbol
        if inferred is not None:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.types[self.current_scope][target.id] = inferred
        for target in node.targets:
            self.visit(target)

    def _add_field(
        self,
        name: str,
        node: ast.AST,
        annotation: ExpressionSummary | None,
        value: ExpressionSummary | None,
        is_annotated: bool,
    ) -> None:
        if self.current_scope is not None and self.current_scope not in self.class_symbols:
            return
        symbol = self._child_symbol(self.current_scope, name)
        self.fields.append(
            FieldFact(
                id=self._fact_id(FactKind.FIELD, symbol.value),
                module_id=self.source.module_id,
                owner_symbol=self.current_scope,
                symbol_id=symbol,
                name=name,
                annotation=annotation,
                value=value,
                is_annotated=is_annotated,
                location=self._location(node),
                provenance=self._provenance(node),
                context=self._syntax_context(),
            )
        )
