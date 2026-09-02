from __future__ import annotations

import ast
from collections.abc import Callable

from taut.analysis.python.resolver_primitives import written_name
from taut.domain.facts import (
    CallArgument,
    ExpressionSummary,
    FunctionParameter,
    ResolutionState,
    SymbolRef,
)
from taut.domain.ids import SymbolId
from taut.domain.location import SourceRange

type Resolve = Callable[[ast.AST], SymbolRef]
type Write = Callable[[ast.AST], str]


class ExpressionSummarizer:
    def __init__(
        self,
        resolve: Resolve,
        write: Write = written_name,
        location: Callable[[ast.AST], SourceRange] | None = None,
    ) -> None:
        self._resolve = resolve
        self._write = write
        self._location = location
        self._expressions: dict[ast.AST, ExpressionSummary] = {}
        self._arguments: dict[ast.Call, tuple[CallArgument, ...]] = {}
        self._symbols_by_node: dict[ast.AST, tuple[SymbolId, ...]] = {}

    def symbols(self, node: ast.AST) -> tuple[SymbolId, ...]:
        cached = self._symbols_by_node.get(node)
        if cached is not None:
            return cached
        symbols: set[SymbolId] = set()
        if isinstance(node, (ast.Name, ast.Attribute)):
            ref = self._resolve(node)
            if ref.state is ResolutionState.RESOLVED and ref.symbol is not None:
                symbols.add(ref.symbol)
        for child in ast.iter_child_nodes(node):
            symbols.update(self.symbols(child))
        result = tuple(sorted(symbols))
        self._symbols_by_node[node] = result
        return result

    def arguments(self, node: ast.Call) -> tuple[CallArgument, ...]:
        cached = self._arguments.get(node)
        if cached is not None:
            return cached
        result: list[CallArgument] = []
        for argument in node.args:
            result.append(CallArgument(None, len(result), self.expression(argument)))
        for keyword in node.keywords:
            result.append(CallArgument(keyword.arg, len(result), self.expression(keyword.value)))
        arguments = tuple(result)
        self._arguments[node] = arguments
        return arguments

    def expression(self, node: ast.AST) -> ExpressionSummary:
        cached = self._expressions.get(node)
        if cached is not None:
            return cached
        literal_kind: str | None = None
        literal_value: str | None = None
        collection_size: int | None = None
        arguments: tuple[CallArgument, ...] = ()
        has_unpack = False
        mapping_keys: tuple[str, ...] | None = None
        if isinstance(node, ast.Constant):
            literal_kind = type(node.value).__name__
            literal_value = repr(node.value)
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            collection_size = len(node.elts)
            has_unpack = any(isinstance(item, ast.Starred) for item in node.elts)
        elif isinstance(node, ast.Dict):
            collection_size = len(node.keys)
            has_unpack = any(key is None for key in node.keys)
            keys = tuple(
                key.value
                for key in node.keys
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
            )
            if not has_unpack and len(keys) == len(node.keys):
                mapping_keys = tuple(sorted(set(keys)))
        elif isinstance(node, ast.Call):
            arguments = self.arguments(node)
            has_unpack = any(
                argument.name is None and argument.value.kind == "Starred" for argument in arguments
            ) or any(keyword.arg is None for keyword in node.keywords)
        kind = node.__class__.__name__
        written = self._write(node).strip() or kind
        summary = ExpressionSummary(
            kind=kind,
            written=written,
            symbols=self.symbols(node),
            literal_kind=literal_kind,
            literal_value=literal_value,
            collection_size=collection_size,
            arguments=arguments,
            has_unpack=has_unpack,
            is_dynamic_string=_is_dynamic_string(node),
            mapping_keys=mapping_keys,
        )
        self._expressions[node] = summary
        return summary

    def parameters(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> tuple[FunctionParameter, ...]:
        positional = (*node.args.posonlyargs, *node.args.args)
        default_start = len(positional) - len(node.args.defaults)
        result = [
            FunctionParameter(
                argument.arg,
                self.expression(argument.annotation) if argument.annotation is not None else None,
                index >= default_start,
                self.expression(node.args.defaults[index - default_start])
                if index >= default_start
                else None,
                self._location(node.args.defaults[index - default_start])
                if index >= default_start and self._location is not None
                else None,
            )
            for index, argument in enumerate(positional)
        ]
        result.extend(
            FunctionParameter(
                argument.arg,
                self.expression(argument.annotation) if argument.annotation is not None else None,
                default is not None,
                self.expression(default) if default is not None else None,
                self._location(default) if default is not None and self._location else None,
            )
            for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True)
        )
        for argument in (node.args.vararg, node.args.kwarg):
            if argument is not None:
                result.append(
                    FunctionParameter(
                        argument.arg,
                        self.expression(argument.annotation)
                        if argument.annotation is not None
                        else None,
                        False,
                        None,
                        None,
                    )
                )
        return tuple(result)


def summarize_arguments(node: ast.Call, resolve: Resolve) -> tuple[CallArgument, ...]:
    return ExpressionSummarizer(resolve).arguments(node)


def summarize_expression(node: ast.AST, resolve: Resolve) -> ExpressionSummary:
    return ExpressionSummarizer(resolve).expression(node)


def _is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp):
        return any(
            isinstance(child, ast.Constant) and isinstance(child.value, str)
            for child in ast.walk(node)
        )
    return bool(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"format", "join"}
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str)
    )


def summarize_parameters(
    node: ast.FunctionDef | ast.AsyncFunctionDef, resolve: Resolve
) -> tuple[FunctionParameter, ...]:
    return ExpressionSummarizer(resolve).parameters(node)
