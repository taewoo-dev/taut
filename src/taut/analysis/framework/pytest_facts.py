from __future__ import annotations

from dataclasses import dataclass

from taut.domain.facts import FunctionFact, ResolutionState
from taut.domain.ids import ModuleId, SymbolId
from taut.domain.provenance import Provenance

PYTEST_PROVIDER_ID = "taut.pytest"
PYTEST_PROVIDER_VERSION = "1"
PYTEST_FIXTURES = "taut.pytest.fixtures@1"


@dataclass(frozen=True, order=True)
class PytestFixtureFact:
    symbol: SymbolId
    module_id: ModuleId
    function: FunctionFact
    dependencies: tuple[str, ...]
    confidence: ResolutionState
    provenance: Provenance

    @property
    def name(self) -> str:
        return self.function.name
