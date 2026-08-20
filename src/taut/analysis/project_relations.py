from __future__ import annotations

from taut.domain.facts import ModuleFacts, ProjectIndex
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId
from taut.domain.relations import ModuleRelations, ProjectRelations


def build_project_relations(
    modules: FrozenMap[ModuleId, ModuleFacts],
    project: ProjectIndex,
    module_relations: tuple[ModuleRelations, ...] = (),
) -> ProjectRelations:
    supplied = tuple(binding for relations in module_relations for binding in relations.bindings)
    bindings = tuple(
        sorted(
            supplied,
            key=lambda item: (
                item.location.path.value,
                item.location.start_line,
                item.location.start_column,
                item.id.value,
            ),
        )
    )
    supplied_uses = tuple(edge for relations in module_relations for edge in relations.use_edges)
    use_edges = tuple(sorted(supplied_uses, key=lambda item: item.occurrence_id.value))
    return ProjectRelations(bindings, project.import_edges, use_edges)
