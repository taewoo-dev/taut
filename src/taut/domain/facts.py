from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from taut.domain.analysis_state import (
    AnalysisStage,
    CompletenessState,
    FactKind,
    IncompleteReason,
    ModuleCompleteness,
)
from taut.domain.frozen import FrozenMap
from taut.domain.ids import FactId, ModuleId, SymbolId
from taut.domain.location import ProjectPath, SourceRange
from taut.domain.provenance import Provenance

__all__ = [
    "AnalysisStage",
    "CompletenessState",
    "FactKind",
    "IncompleteReason",
    "ModuleCompleteness",
]


class SourceKind(StrEnum):
    FIRST_PARTY = "first_party"
    THIRD_PARTY = "third_party"
    STUB = "stub"
    GENERATED = "generated"


class ResolutionState(StrEnum):
    RESOLVED = "resolved"
    CONDITIONAL = "conditional"
    UNRESOLVED = "unresolved"
    AMBIGUOUS = "ambiguous"
    DYNAMIC = "dynamic"


class ScopeKind(StrEnum):
    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"
    LAMBDA = "lambda"
    COMPREHENSION = "comprehension"


class SyntaxPosition(StrEnum):
    BODY = "body"
    ANNOTATION = "annotation"
    DECORATOR = "decorator"
    BASE = "base"
    DEFAULT = "default"
    ARGUMENT = "argument"
    METADATA = "metadata"
    CONTEXT_MANAGER = "context_manager"


class ExecutionPhase(StrEnum):
    MODULE_INIT = "module_init"
    DEFERRED = "deferred"


class GuardKind(StrEnum):
    UNCONDITIONAL = "unconditional"
    CONDITIONAL = "conditional"
    TYPE_CHECKING_ONLY = "type_checking_only"


class ImportIntent(StrEnum):
    NORMAL = "normal"
    OPTIONAL_DEPENDENCY = "optional_dependency"


@dataclass(frozen=True, order=True)
class SyntaxContext:
    lexical_owner: SymbolId | None = None
    scope_kind: ScopeKind = ScopeKind.MODULE
    position: SyntaxPosition = SyntaxPosition.BODY
    execution_phase: ExecutionPhase = ExecutionPhase.MODULE_INIT
    guard: GuardKind = GuardKind.UNCONDITIONAL
    parent_fact_id: FactId | None = None
    argument_name: str | None = None
    argument_position: int | None = None

    def __post_init__(self) -> None:
        if self.argument_name is not None and not self.argument_name.strip():
            raise ValueError("syntax context argument name cannot be empty")
        if self.argument_position is not None and self.argument_position < 0:
            raise ValueError("syntax context argument position cannot be negative")
        if self.position is not SyntaxPosition.ARGUMENT and (
            self.argument_name is not None or self.argument_position is not None
        ):
            raise ValueError("argument metadata is only valid in argument position")


@dataclass(frozen=True, order=True)
class SymbolRef:
    written_name: str
    state: ResolutionState
    symbol: SymbolId | None
    candidates: tuple[SymbolId, ...]
    provenance: Provenance

    def __post_init__(self) -> None:
        if not self.written_name.strip():
            raise ValueError("written symbol name cannot be empty")
        if self.state is ResolutionState.RESOLVED:
            if self.symbol is None or self.candidates:
                raise ValueError("resolved symbol must have one symbol and no candidates")
        elif self.symbol is not None:
            raise ValueError("non-resolved symbol cannot have a selected symbol")
        if self.state is ResolutionState.AMBIGUOUS and len(self.candidates) < 2:
            raise ValueError("ambiguous symbol must have at least two candidates")
        if self.state is ResolutionState.CONDITIONAL and not self.candidates:
            raise ValueError("conditional symbol must have at least one candidate")
        if (
            self.state not in (ResolutionState.AMBIGUOUS, ResolutionState.CONDITIONAL)
            and self.candidates
        ):
            raise ValueError("only ambiguous or conditional symbols can have candidates")


@dataclass(frozen=True)
class ExpressionSummary:
    """Stable, language-neutral details needed by policy rules."""

    kind: str
    written: str
    symbols: tuple[SymbolId, ...]
    literal_kind: str | None = None
    literal_value: str | None = None
    collection_size: int | None = None
    arguments: tuple[CallArgument, ...] = ()
    has_unpack: bool = False
    is_dynamic_string: bool = False
    mapping_keys: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        if not self.kind.strip() or not self.written.strip():
            raise ValueError("expression kind and written form cannot be empty")
        if self.symbols != tuple(sorted(set(self.symbols))):
            raise ValueError("expression symbols must be unique and sorted")
        if self.collection_size is not None and self.collection_size < 0:
            raise ValueError("expression collection size cannot be negative")
        if self.mapping_keys is not None and self.mapping_keys != tuple(
            sorted(set(self.mapping_keys))
        ):
            raise ValueError("mapping keys must be unique and sorted")


@dataclass(frozen=True)
class CallArgument:
    name: str | None
    position: int
    value: ExpressionSummary

    def __post_init__(self) -> None:
        if self.position < 0:
            raise ValueError("call argument position cannot be negative")
        if self.name is not None and not self.name.strip():
            raise ValueError("call argument name cannot be empty")


@dataclass(frozen=True)
class FunctionParameter:
    name: str
    annotation: ExpressionSummary | None
    has_default: bool
    default_expression: ExpressionSummary | None = None
    default_location: SourceRange | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("function parameter name cannot be empty")


@dataclass(frozen=True, order=True)
class ModuleIdentity:
    id: ModuleId
    path: ProjectPath
    kind: SourceKind
    is_policy_target: bool
    is_package: bool
    line_count: int

    def __post_init__(self) -> None:
        if self.line_count < 0:
            raise ValueError("line count cannot be negative")


@dataclass(frozen=True, order=True)
class ImportFact:
    id: FactId
    module_id: ModuleId
    imported_name: str
    imported_module_name: str
    alias: str | None
    is_from: bool
    relative_level: int
    enclosing_symbol: SymbolId | None
    location: SourceRange
    provenance: Provenance
    context: SyntaxContext
    intent: ImportIntent = ImportIntent.NORMAL


@dataclass(frozen=True, order=True)
class DefinitionFact:
    id: FactId
    module_id: ModuleId
    symbol_id: SymbolId
    kind: str
    enclosing_symbol: SymbolId | None
    location: SourceRange
    provenance: Provenance
    context: SyntaxContext


@dataclass(frozen=True, order=True)
class ReferenceFact:
    id: FactId
    module_id: ModuleId
    ref: SymbolRef
    enclosing_symbol: SymbolId | None
    location: SourceRange
    provenance: Provenance
    context: SyntaxContext


@dataclass(frozen=True, order=True)
class CallFact:
    id: FactId
    module_id: ModuleId
    ref: SymbolRef
    enclosing_symbol: SymbolId | None
    positional_argument_count: int
    keyword_names: tuple[str, ...]
    has_keyword_unpack: bool
    arguments: tuple[CallArgument, ...]
    enclosing_contexts: tuple[SymbolRef, ...]
    location: SourceRange
    provenance: Provenance
    context: SyntaxContext

    def __post_init__(self) -> None:
        if self.positional_argument_count < 0:
            raise ValueError("call positional argument count cannot be negative")
        if self.keyword_names != tuple(sorted(set(self.keyword_names))):
            raise ValueError("call keyword names must be unique and sorted")
        positions = tuple(argument.position for argument in self.arguments)
        if positions != tuple(range(len(self.arguments))):
            raise ValueError("call argument positions must be contiguous")


@dataclass(frozen=True, order=True)
class DecoratorFact:
    id: FactId
    module_id: ModuleId
    decorated_symbol: SymbolId
    ref: SymbolRef
    arguments: tuple[CallArgument, ...]
    location: SourceRange
    provenance: Provenance
    context: SyntaxContext


@dataclass(frozen=True, order=True)
class FunctionFact:
    id: FactId
    module_id: ModuleId
    symbol_id: SymbolId
    name: str
    is_async: bool
    decorators: tuple[SymbolRef, ...]
    parameters: tuple[FunctionParameter, ...]
    return_annotation: ExpressionSummary | None
    has_docstring: bool
    location: SourceRange
    provenance: Provenance
    context: SyntaxContext
    returned_mapping_keys: tuple[str, ...] | None = None
    returned_symbols: tuple[SymbolId, ...] = ()


@dataclass(frozen=True)
class ClassFact:
    id: FactId
    module_id: ModuleId
    symbol_id: SymbolId
    name: str
    bases: tuple[ExpressionSummary, ...]
    has_docstring: bool
    location: SourceRange
    provenance: Provenance
    context: SyntaxContext


@dataclass(frozen=True)
class FieldFact:
    id: FactId
    module_id: ModuleId
    owner_symbol: SymbolId | None
    symbol_id: SymbolId
    name: str
    annotation: ExpressionSummary | None
    value: ExpressionSummary | None
    is_annotated: bool
    location: SourceRange
    provenance: Provenance
    context: SyntaxContext


@dataclass(frozen=True, order=True)
class BindingFact:
    id: FactId
    module_id: ModuleId
    local_name: str
    kind: str
    lexical_owner: SymbolId | None
    symbol_id: SymbolId
    location: SourceRange
    provenance: Provenance
    context: SyntaxContext


type LocatedFact = (
    ImportFact
    | DefinitionFact
    | ReferenceFact
    | CallFact
    | DecoratorFact
    | FunctionFact
    | ClassFact
    | FieldFact
    | BindingFact
)


def _location_key(value: LocatedFact) -> tuple[str, int, int, str]:
    location = value.location
    identifier = value.id
    return (
        location.path.value,
        location.start_line,
        location.start_column,
        str(identifier),
    )


def _validate_fact_collection[T: LocatedFact](
    values: tuple[T, ...],
    module_id: ModuleId,
) -> None:
    if values != tuple(sorted(values, key=_location_key)):
        raise ValueError("module fact collections must be in source order")
    if any(value.module_id != module_id for value in values):
        raise ValueError("all facts must belong to their ModuleFacts owner")


@dataclass(frozen=True)
class ModuleFacts:
    module: ModuleIdentity
    imports: tuple[ImportFact, ...]
    definitions: tuple[DefinitionFact, ...]
    references: tuple[ReferenceFact, ...]
    calls: tuple[CallFact, ...]
    decorators: tuple[DecoratorFact, ...]
    functions: tuple[FunctionFact, ...]
    classes: tuple[ClassFact, ...]
    fields: tuple[FieldFact, ...]
    bindings: tuple[BindingFact, ...]
    completeness: ModuleCompleteness

    def __post_init__(self) -> None:
        _validate_fact_collection(self.imports, self.module.id)
        _validate_fact_collection(self.definitions, self.module.id)
        _validate_fact_collection(self.references, self.module.id)
        _validate_fact_collection(self.calls, self.module.id)
        _validate_fact_collection(self.decorators, self.module.id)
        _validate_fact_collection(self.functions, self.module.id)
        _validate_fact_collection(self.classes, self.module.id)
        _validate_fact_collection(self.fields, self.module.id)
        _validate_fact_collection(self.bindings, self.module.id)


@dataclass(frozen=True, order=True)
class UnresolvedImport:
    importer: ModuleId
    written_name: str
    location: SourceRange
    reason: str


@dataclass(frozen=True, order=True)
class ImportEdge:
    importer: ModuleId
    target: ModuleId
    occurrence_id: FactId
    location: SourceRange
    context: SyntaxContext

    @property
    def is_eager_runtime(self) -> bool:
        return (
            self.context.guard is not GuardKind.TYPE_CHECKING_ONLY
            and self.context.execution_phase is ExecutionPhase.MODULE_INIT
        )

    @property
    def is_deferred_runtime(self) -> bool:
        return (
            self.context.guard is not GuardKind.TYPE_CHECKING_ONLY
            and self.context.execution_phase is ExecutionPhase.DEFERRED
        )

    @property
    def is_type_only(self) -> bool:
        return self.context.guard is GuardKind.TYPE_CHECKING_ONLY


@dataclass(frozen=True, order=True)
class CycleEdge:
    importer: ModuleId
    target: ModuleId
    location: SourceRange
    occurrence_id: FactId


@dataclass(frozen=True, order=True)
class ImportCycle:
    modules: tuple[ModuleId, ...]
    edges: tuple[CycleEdge, ...] = ()

    def __post_init__(self) -> None:
        if not self.modules:
            raise ValueError("an import cycle must contain at least one module")
        if len(set(self.modules)) != len(self.modules):
            raise ValueError("cycle modules must be unique")
        if self.edges:
            if len(self.edges) != len(self.modules):
                raise ValueError("cycle witness must contain one edge per module")
            for index, edge in enumerate(self.edges):
                if edge.importer != self.modules[index]:
                    raise ValueError("cycle edge importer must match cycle module order")
                if edge.target != self.modules[(index + 1) % len(self.modules)]:
                    raise ValueError("cycle edges must form a directed cycle")
        elif self.modules != tuple(sorted(self.modules)):
            raise ValueError("cycles without edge witnesses must use canonical sorted order")


@dataclass(frozen=True)
class ProjectIndex:
    imports: FrozenMap[ModuleId, tuple[ModuleId, ...]]
    imported_by: FrozenMap[ModuleId, tuple[ModuleId, ...]]
    unresolved_imports: tuple[UnresolvedImport, ...]
    cycles: tuple[ImportCycle, ...]
    import_edges: tuple[ImportEdge, ...] = ()
    type_imports: FrozenMap[ModuleId, tuple[ModuleId, ...]] = field(
        default_factory=lambda: FrozenMap[ModuleId, tuple[ModuleId, ...]]()
    )
    deferred_imports: FrozenMap[ModuleId, tuple[ModuleId, ...]] = field(
        default_factory=lambda: FrozenMap[ModuleId, tuple[ModuleId, ...]]()
    )
    canonical_symbols: FrozenMap[SymbolId, SymbolId] = field(
        default_factory=lambda: FrozenMap[SymbolId, SymbolId]()
    )

    def __post_init__(self) -> None:
        if set(self.imports) != set(self.imported_by):
            raise ValueError("imports and imported_by must contain the same modules")
        for source, targets in self.imports.items():
            if targets != tuple(sorted(set(targets))):
                raise ValueError("import targets must be unique and sorted")
            for target in targets:
                if source not in self.imported_by.get(target, ()):
                    raise ValueError("imports and imported_by must be symmetric")
        for target, sources in self.imported_by.items():
            if sources != tuple(sorted(set(sources))):
                raise ValueError("reverse import sources must be unique and sorted")
            for source in sources:
                if target not in self.imports.get(source, ()):
                    raise ValueError("imported_by and imports must be symmetric")
        if any(alias == canonical for alias, canonical in self.canonical_symbols.items()):
            raise ValueError("canonical symbol aliases must not map to themselves")
        if any(
            canonical in self.canonical_symbols for canonical in self.canonical_symbols.values()
        ):
            raise ValueError("canonical symbol aliases must point directly to a canonical symbol")
