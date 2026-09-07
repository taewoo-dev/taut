"""Translate framework-owned facts into policy-facing database operations."""

from __future__ import annotations

from dataclasses import dataclass

from taut.analysis.framework.tortoise_facts import TortoiseQueryFact, TortoiseTransactionFact
from taut.analysis.semantic_model import SemanticModel
from taut.domain.database_operations import DatabaseOperation
from taut.domain.frozen import FrozenMap
from taut.domain.ids import FactId


@dataclass(frozen=True)
class DatabaseOperationIndex:
    queries: FrozenMap[FactId, DatabaseOperation]
    transactions: FrozenMap[FactId, DatabaseOperation]

    @classmethod
    def build(cls, model: SemanticModel) -> DatabaseOperationIndex:
        queries = FrozenMap(
            (
                fact.call.id,
                DatabaseOperation("tortoise", fact.operation, fact.confidence, fact.is_write),
            )
            for fact in model.capability_values("taut.tortoise.queries@1")
            if isinstance(fact, TortoiseQueryFact)
        )
        transactions = FrozenMap(
            (fact.call.id, DatabaseOperation("tortoise", fact.operation, fact.confidence))
            for fact in model.capability_values("taut.tortoise.transactions@1")
            if isinstance(fact, TortoiseTransactionFact)
        )
        return cls(queries, transactions)
