from __future__ import annotations

from taut.analysis.framework.pytest_facts import (
    PYTEST_FIXTURES,
    PYTEST_PROVIDER_ID,
    PYTEST_PROVIDER_VERSION,
    PytestFixtureFact,
)
from taut.analysis.providers import CapabilitySpec
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId
from taut.domain.snapshot import AnalysisSnapshot


class PytestProvider:
    id = PYTEST_PROVIDER_ID
    version = PYTEST_PROVIDER_VERSION
    provides = frozenset({CapabilitySpec(PYTEST_FIXTURES)})

    def analyze(self, snapshot: AnalysisSnapshot) -> FrozenMap[str, tuple[object, ...]]:
        fixtures: list[PytestFixtureFact] = []
        for module in snapshot.modules.values():
            decorators = {
                item.decorated_symbol: item
                for item in module.decorators
                if item.ref.written_name in {"fixture", "pytest.fixture"}
                or (
                    item.ref.symbol is not None
                    and item.ref.symbol.value in {"pytest.fixture", "_pytest.fixtures.fixture"}
                )
            }
            fixtures.extend(
                PytestFixtureFact(
                    function.symbol_id,
                    function.module_id,
                    function,
                    tuple(sorted(parameter.name for parameter in function.parameters)),
                    decorators[function.symbol_id].ref.state,
                    function.provenance,
                )
                for function in module.functions
                if function.symbol_id in decorators
            )
        return FrozenMap(((PYTEST_FIXTURES, tuple(sorted(fixtures))),))

    def analyze_incremental(
        self,
        snapshot: AnalysisSnapshot,
        previous: FrozenMap[str, tuple[object, ...]],
        impacted: frozenset[ModuleId],
    ) -> FrozenMap[str, tuple[object, ...]]:
        del previous, impacted
        return self.analyze(snapshot)


__all__ = [
    "PYTEST_FIXTURES",
    "PYTEST_PROVIDER_ID",
    "PytestFixtureFact",
    "PytestProvider",
]
