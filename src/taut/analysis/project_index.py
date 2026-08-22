from __future__ import annotations

from collections.abc import Iterable

from taut.domain.facts import (
    CycleEdge,
    ImportCycle,
    ImportEdge,
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
    runtime_imports: dict[ModuleId, set[ModuleId]] = {module_id: set() for module_id in module_ids}
    eager_imports: dict[ModuleId, set[ModuleId]] = {module_id: set() for module_id in module_ids}
    type_imports: dict[ModuleId, set[ModuleId]] = {module_id: set() for module_id in module_ids}
    deferred_imports: dict[ModuleId, set[ModuleId]] = {module_id: set() for module_id in module_ids}
    edges: list[ImportEdge] = []
    unresolved: list[UnresolvedImport] = []

    for facts in module_list:
        for import_fact in facts.imports:
            target = _resolve_internal_import(
                import_fact.imported_name,
                import_fact.imported_module_name,
                modules_by_name,
            )
            if target is not None:
                edge = ImportEdge(
                    facts.module.id,
                    target,
                    import_fact.id,
                    import_fact.location,
                    import_fact.context,
                )
                edges.append(edge)
                if edge.is_type_only:
                    type_imports[facts.module.id].add(target)
                else:
                    runtime_imports[facts.module.id].add(target)
                    if edge.is_eager_runtime:
                        eager_imports[facts.module.id].add(target)
                    elif edge.is_deferred_runtime:
                        deferred_imports[facts.module.id].add(target)
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
        (source, tuple(sorted(targets))) for source, targets in runtime_imports.items()
    )
    reverse: dict[ModuleId, set[ModuleId]] = {module_id: set() for module_id in module_ids}
    for source, targets in runtime_imports.items():
        for target in targets:
            reverse[target].add(source)
    frozen_reverse = FrozenMap(
        (target, tuple(sorted(sources))) for target, sources in reverse.items()
    )
    frozen_eager = FrozenMap(
        (source, tuple(sorted(targets))) for source, targets in eager_imports.items()
    )
    ordered_edges = tuple(
        sorted(
            edges,
            key=lambda edge: (
                edge.importer.value,
                edge.target.value,
                edge.location.path.value,
                edge.location.start_line,
                edge.location.start_column,
                edge.occurrence_id.value,
            ),
        )
    )
    cycles = _find_cycles(frozen_eager, ordered_edges)
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
        import_edges=ordered_edges,
        type_imports=FrozenMap(
            (source, tuple(sorted(targets))) for source, targets in type_imports.items()
        ),
        deferred_imports=FrozenMap(
            (source, tuple(sorted(targets))) for source, targets in deferred_imports.items()
        ),
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
    edges: tuple[ImportEdge, ...],
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

    edge_by_pair: dict[tuple[ModuleId, ModuleId], ImportEdge] = {}
    for edge in edges:
        if not edge.is_eager_runtime:
            continue
        edge_by_pair.setdefault((edge.importer, edge.target), edge)
    return tuple(_cycle_witness(component, graph, edge_by_pair) for component in sorted(components))


def _cycle_witness(
    component: tuple[ModuleId, ...],
    graph: FrozenMap[ModuleId, tuple[ModuleId, ...]],
    edge_by_pair: dict[tuple[ModuleId, ModuleId], ImportEdge],
) -> ImportCycle:
    members = frozenset(component)
    start = component[0]
    path: tuple[ModuleId, ...]
    if start in graph[start]:
        path = (start,)
    else:
        path_result = _path_back_to(start, start, graph, members, frozenset())
        if path_result is None:
            raise ValueError("strongly connected component has no cycle witness")
        path = path_result
    cycle_edges: list[CycleEdge] = []
    for index, importer in enumerate(path):
        target = path[(index + 1) % len(path)]
        edge = edge_by_pair[(importer, target)]
        cycle_edges.append(CycleEdge(importer, target, edge.location, edge.occurrence_id))
    return ImportCycle(path, tuple(cycle_edges))


def _path_back_to(
    start: ModuleId,
    current: ModuleId,
    graph: FrozenMap[ModuleId, tuple[ModuleId, ...]],
    members: frozenset[ModuleId],
    visited: frozenset[ModuleId],
) -> tuple[ModuleId, ...] | None:
    next_visited = visited.union({current})
    for target in graph[current]:
        if target not in members:
            continue
        if target == start and current != start:
            return (current,)
        if target in next_visited:
            continue
        suffix = _path_back_to(start, target, graph, members, next_visited)
        if suffix is not None:
            return (current, *suffix)
    return None
