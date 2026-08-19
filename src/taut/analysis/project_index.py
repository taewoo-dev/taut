from __future__ import annotations

from collections.abc import Iterable

from taut.domain.facts import (
    ImportCycle,
    ModuleFacts,
    ProjectIndex,
    UnresolvedImport,
)
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId


def build_project_index(modules: Iterable[ModuleFacts]) -> ProjectIndex:
    module_list = tuple(sorted(modules, key=lambda facts: facts.module.id))
    module_ids = frozenset(facts.module.id for facts in module_list)
    modules_by_name = {module_id.value: module_id for module_id in module_ids}
    internal_roots = frozenset(module_id.value.split(".")[0] for module_id in module_ids)
    imports: dict[ModuleId, set[ModuleId]] = {module_id: set() for module_id in module_ids}
    unresolved: list[UnresolvedImport] = []

    for facts in module_list:
        for import_fact in facts.imports:
            target = _resolve_internal_import(
                import_fact.imported_name,
                import_fact.imported_module_name,
                modules_by_name,
            )
            if target is not None:
                imports[facts.module.id].add(target)
                continue
            root = import_fact.imported_module_name.split(".")[0]
            possibly_internal = import_fact.relative_level > 0 or root in internal_roots
            if possibly_internal:
                unresolved.append(
                    UnresolvedImport(
                        importer=facts.module.id,
                        written_name=import_fact.imported_name,
                        location=import_fact.location,
                        reason="프로젝트 내부 모듈로 연결하지 못했습니다.",
                    )
                )

    frozen_imports = FrozenMap(
        (source, tuple(sorted(targets))) for source, targets in imports.items()
    )
    reverse: dict[ModuleId, set[ModuleId]] = {module_id: set() for module_id in module_ids}
    for source, targets in imports.items():
        for target in targets:
            reverse[target].add(source)
    frozen_reverse = FrozenMap(
        (target, tuple(sorted(sources))) for target, sources in reverse.items()
    )
    cycles = _find_cycles(frozen_imports)
    return ProjectIndex(
        imports=frozen_imports,
        imported_by=frozen_reverse,
        unresolved_imports=tuple(
            sorted(
                unresolved,
                key=lambda item: (
                    item.location.path.value,
                    item.location.start_line,
                    item.location.start_column,
                    item.written_name,
                ),
            )
        ),
        cycles=cycles,
    )


def _resolve_internal_import(
    imported_name: str,
    imported_module_name: str,
    modules_by_name: dict[str, ModuleId],
) -> ModuleId | None:
    candidates = (imported_name, imported_module_name)
    for candidate in candidates:
        current = candidate
        while current:
            module_id = modules_by_name.get(current)
            if module_id is not None:
                return module_id
            current = current.rpartition(".")[0]
    return None


def _find_cycles(
    graph: FrozenMap[ModuleId, tuple[ModuleId, ...]],
) -> tuple[ImportCycle, ...]:
    index = 0
    stack: list[ModuleId] = []
    on_stack: set[ModuleId] = set()
    indexes: dict[ModuleId, int] = {}
    low_links: dict[ModuleId, int] = {}
    components: list[tuple[ModuleId, ...]] = []

    def visit(node: ModuleId) -> None:
        nonlocal index
        indexes[node] = index
        low_links[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)

        for target in graph[node]:
            if target not in indexes:
                visit(target)
                low_links[node] = min(low_links[node], low_links[target])
            elif target in on_stack:
                low_links[node] = min(low_links[node], indexes[target])

        if low_links[node] != indexes[node]:
            return
        component: list[ModuleId] = []
        while True:
            member = stack.pop()
            on_stack.remove(member)
            component.append(member)
            if member == node:
                break
        ordered = tuple(sorted(component))
        if len(ordered) > 1 or (len(ordered) == 1 and ordered[0] in graph[ordered[0]]):
            components.append(ordered)

    for module_id in graph:
        if module_id not in indexes:
            visit(module_id)

    return tuple(ImportCycle(component) for component in sorted(components))
