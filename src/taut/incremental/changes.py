from __future__ import annotations

from dataclasses import dataclass

from taut.analysis.contracts import SourceInput
from taut.domain.facts import ProjectIndex
from taut.domain.ids import ModuleId


@dataclass(frozen=True)
class ChangeSet:
    added: frozenset[ModuleId]
    changed: frozenset[ModuleId]
    removed: frozenset[ModuleId]

    @property
    def touched(self) -> frozenset[ModuleId]:
        return self.added | self.changed | self.removed

    @classmethod
    def compare(cls, old: tuple[SourceInput, ...], new: tuple[SourceInput, ...]) -> ChangeSet:
        before = {item.module_id: item for item in old}
        after = {item.module_id: item for item in new}
        return cls(
            frozenset(after.keys() - before.keys()),
            frozenset(
                module for module in before.keys() & after.keys() if before[module] != after[module]
            ),
            frozenset(before.keys() - after.keys()),
        )


@dataclass(frozen=True)
class ImpactGraph:
    impacted: frozenset[ModuleId]

    @classmethod
    def from_indexes(
        cls, changes: ChangeSet, old: ProjectIndex | None, new: ProjectIndex | None
    ) -> ImpactGraph:
        reverse: dict[ModuleId, set[ModuleId]] = {}
        for index in (old, new):
            if index is not None:
                for module, dependents in index.imported_by.items():
                    reverse.setdefault(module, set()).update(dependents)
        impacted = set(changes.added | changes.changed | changes.removed)
        queue = list(impacted)
        while queue:
            module = queue.pop()
            for dependent in reverse.get(module, ()):
                if dependent not in impacted:
                    impacted.add(dependent)
                    queue.append(dependent)
        return cls(frozenset(impacted))
