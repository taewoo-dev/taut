from __future__ import annotations

from collections.abc import Callable

from taut.analysis.framework.pydantic_facts import PydanticModelFact
from taut.domain.facts import ClassFact, ResolutionState, SymbolRef
from taut.domain.ids import ModuleId, SymbolId
from taut.domain.relations import UseEdge
from taut.domain.snapshot import AnalysisSnapshot


def extract_pydantic_models(
    snapshot: AnalysisSnapshot,
    classes: tuple[ClassFact, ...],
    inherited_models: frozenset[SymbolId],
    base_symbols: frozenset[SymbolId],
    base_ref: Callable[
        [
            AnalysisSnapshot,
            ClassFact,
            str,
            tuple[SymbolId, ...],
            dict[tuple[ModuleId, str], tuple[UseEdge, ...]],
        ],
        SymbolRef,
    ],
) -> tuple[PydanticModelFact, ...]:
    known = set(base_symbols | inherited_models)
    by_name: dict[tuple[ModuleId, str], list[UseEdge]] = {}
    for edge in snapshot.relations.use_edges:
        if edge.purpose.value == "base":
            by_name.setdefault((edge.module_id, edge.ref.written_name), []).append(edge)
    indexed = {key: tuple(edges) for key, edges in by_name.items()}
    result: list[PydanticModelFact] = []
    pending = list(classes)
    while pending:
        rest: list[ClassFact] = []
        progress = False
        for item in pending:
            refs = tuple(
                base_ref(snapshot, item, base.written, base.symbols, indexed) for base in item.bases
            )
            relevant = tuple(
                ref
                for ref in refs
                if ref.symbol in known or any(candidate in known for candidate in ref.candidates)
            )
            if not relevant:
                rest.append(item)
                continue
            progress = True
            confidence = relevant[0].state
            if any(ref.state is ResolutionState.AMBIGUOUS for ref in relevant):
                confidence = ResolutionState.AMBIGUOUS
            known.add(item.symbol_id)
            result.append(
                PydanticModelFact(
                    item.symbol_id,
                    item.module_id,
                    item,
                    relevant[0],
                    relevant,
                    confidence,
                    item.provenance,
                )
            )
        if not progress:
            break
        pending = rest
    return tuple(
        sorted(result, key=lambda item: (item.module_id, item.class_fact.location, item.symbol))
    )
