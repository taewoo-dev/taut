CONTRACT_VERSION: int
BATCH_VERSION: int

NativeValue = tuple[int, int, list[str], list[str], int]
NativeRow = tuple[str, str, list[str], NativeValue]

NativeFunction = tuple[str, str, str]
NativeCalls = tuple[
    list[str], list[str], list[str | None], list[str], list[int], list[int], list[int]
]
NativeBatch = tuple[list[NativeFunction], NativeCalls, list[tuple[str, str]]]

class State:
    @staticmethod
    def build_batch(batch: NativeBatch) -> State: ...
    def advance_batch(self, changed: list[str], batch: NativeBatch) -> State: ...
    reused_components: int
    recomputed_components: int
    compute_seconds: float
    @staticmethod
    def build(rows: list[NativeRow]) -> State: ...
    def advance(self, changed_modules: list[str], rows: list[NativeRow]) -> State: ...
    def export(self) -> list[tuple[str, NativeValue]]: ...
    def export_compact(self) -> tuple[list[NativeValue], list[tuple[str, int]]]: ...
    def export_direct(self) -> list[tuple[str, NativeValue]]: ...
    def export_graph(self) -> list[tuple[str, list[str]]]: ...
    def stats(self) -> tuple[int, int, int, int]: ...

AtomicFunction = tuple[str, str, list[str]]
AtomicCalls = tuple[
    list[str],
    list[str],
    list[str | None],
    list[str | None],
    list[tuple[str, ...]],
    list[str],
    list[tuple[str, ...]],
    list[int],
]
AtomicBatch = tuple[
    list[AtomicFunction], AtomicCalls, list[tuple[str, list[str]]], list[str], list[str]
]
AtomicContribution = tuple[tuple[int, int], str | None, list[str]]

class AtomicState:
    processed_functions: int
    compute_seconds: float
    @staticmethod
    def build(batch: AtomicBatch) -> AtomicState: ...
    def advance(self, changed: list[str], batch: AtomicBatch) -> AtomicState: ...
    def export(self) -> list[tuple[str, tuple[int, int]]]: ...
    def export_contributions(self) -> list[tuple[str, list[AtomicContribution]]]: ...
