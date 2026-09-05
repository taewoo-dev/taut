from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
from typing import cast

from taut.domain.facts import LocatedFact, ModuleFacts, ModuleIdentity
from taut.domain.frozen import FrozenMap
from taut.domain.ids import FactId, ModuleId
from taut.domain.location import SourceRange
from taut.domain.provenance import Provenance

SEMANTIC_DIGEST_SCHEMA = 1
_OMITTED_FIELDS = frozenset({"location", "default_location"})


@dataclass(frozen=True)
class SemanticDigestIndex:
    """Versioned, location-independent fingerprints for incremental query inputs."""

    schema_version: int
    module_interfaces: FrozenMap[ModuleId, str]
    definitions: FrozenMap[FactId, str]
    calls: FrozenMap[FactId, str]
    bindings: FrozenMap[FactId, str]

    @classmethod
    def build(cls, modules: Iterable[ModuleFacts]) -> SemanticDigestIndex:
        interfaces: list[tuple[ModuleId, str]] = []
        definitions: list[tuple[FactId, str]] = []
        calls: list[tuple[FactId, str]] = []
        bindings: list[tuple[FactId, str]] = []
        for module in sorted(modules, key=lambda item: item.module.id):
            definition_facts: tuple[LocatedFact, ...] = (
                *module.definitions,
                *module.decorators,
                *module.functions,
                *module.classes,
                *module.fields,
            )
            interfaces.append(
                (module.module.id, semantic_digest("module-interface", _module_interface(module)))
            )
            definitions.extend(
                (fact.id, semantic_digest("definition", fact)) for fact in definition_facts
            )
            calls.extend((call.id, semantic_digest("call", call)) for call in module.calls)
            bindings.extend(
                (binding.id, semantic_digest("binding", binding)) for binding in module.bindings
            )
        return cls(
            SEMANTIC_DIGEST_SCHEMA,
            FrozenMap(interfaces),
            FrozenMap(definitions),
            FrozenMap(calls),
            FrozenMap(bindings),
        )


def semantic_digest(namespace: str, value: object) -> str:
    """Hash a semantic value independently from source coordinates and source bytes."""
    if not namespace.strip():
        raise ValueError("semantic digest namespace cannot be empty")
    payload = json.dumps(
        (SEMANTIC_DIGEST_SCHEMA, namespace, _semantic_value(value)),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _module_interface(module: ModuleFacts) -> tuple[object, ...]:
    top_level_symbols = frozenset(
        definition.symbol_id
        for definition in module.definitions
        if definition.enclosing_symbol is None
    )
    return (
        module.module,
        module.completeness,
        tuple(item for item in module.imports if item.enclosing_symbol is None),
        tuple(item for item in module.definitions if item.enclosing_symbol is None),
        tuple(item for item in module.decorators if item.decorated_symbol in top_level_symbols),
        tuple(item for item in module.functions if item.symbol_id in top_level_symbols),
        tuple(item for item in module.classes if item.symbol_id in top_level_symbols),
        tuple(item for item in module.fields if item.owner_symbol is None),
        tuple(item for item in module.bindings if item.lexical_owner is None),
    )


def _semantic_value(value: object) -> object:
    if isinstance(value, Enum):
        return (value.__class__.__name__, value.value)
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (FactId, ModuleId)):
        return (value.__class__.__name__, value.value)
    if isinstance(value, SourceRange):
        return None
    if isinstance(value, Provenance):
        return ("Provenance", value.provider, value.provider_version)
    if isinstance(value, ModuleIdentity):
        return (
            "ModuleIdentity",
            _semantic_value(value.id),
            _semantic_value(value.kind),
            value.is_policy_target,
            value.is_package,
        )
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, object], value)
        items = [(_semantic_value(key), _semantic_value(item)) for key, item in mapping.items()]
        return ("mapping", tuple(sorted(items, key=_sort_key)))
    if isinstance(value, (tuple, list)):
        sequence = cast(tuple[object, ...] | list[object], value)
        return tuple(_semantic_value(item) for item in sequence)
    if isinstance(value, (set, frozenset)):
        collection = cast(set[object] | frozenset[object], value)
        return (
            "set",
            tuple(sorted((_semantic_value(item) for item in collection), key=_sort_key)),
        )
    if is_dataclass(value) and not isinstance(value, type):
        return (
            value.__class__.__name__,
            tuple(
                (field.name, _semantic_value(getattr(value, field.name)))
                for field in fields(value)
                if field.name not in _OMITTED_FIELDS
            ),
        )
    raise TypeError(f"unsupported semantic digest value: {type(value).__qualname__}")


def _sort_key(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
