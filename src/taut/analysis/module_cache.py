"""Bounded, versioned MessagePack cache for module analysis results."""

from __future__ import annotations

import dataclasses
from dataclasses import fields, is_dataclass
from enum import Enum
from typing import TypeAlias, cast

import msgspec.msgpack

from taut.analysis import contracts
from taut.analysis.contracts import AdapterIdentity, ModuleAnalysisResult
from taut.domain import (
    analysis_state,
    diagnostics,
    evaluations,
    facts,
    findings,
    ids,
    issues,
    location,
    provenance,
    relations,
)
from taut.domain.frozen import FrozenMap

CACHE_SCHEMA_VERSION = 1
MAX_PAYLOAD_BYTES = 8 * 1024 * 1024
MAX_NODES = 500_000
MAX_DEPTH = 128


class CacheMissError(ValueError):
    """A cache entry was absent, malformed, incompatible, or unsafe."""


@dataclasses.dataclass(frozen=True)
class CacheMetadata:
    adapter: AdapterIdentity
    resolver_identity: str


@dataclasses.dataclass(frozen=True)
class CacheDecodeResult:
    value: ModuleAnalysisResult | None
    metadata: CacheMetadata | None
    error: str | None = None


_MODULES = (
    contracts,
    analysis_state,
    diagnostics,
    evaluations,
    facts,
    findings,
    ids,
    issues,
    location,
    provenance,
    relations,
)
WireValue: TypeAlias = str | int | bool | None | dict[str, object] | list[object]

_TYPES: dict[str, type[object]] = {
    f"{cls.__module__}.{cls.__name__}": cls
    for module in _MODULES
    for cls in vars(module).values()
    if isinstance(cls, type) and is_dataclass(cls) and cls.__module__ == module.__name__
}
_TYPES[f"{CacheMetadata.__module__}.{CacheMetadata.__name__}"] = CacheMetadata
_ENUMS: dict[str, type[Enum]] = {
    f"{cls.__module__}.{cls.__name__}": cls
    for module in _MODULES
    for cls in vars(module).values()
    if isinstance(cls, type) and issubclass(cls, Enum) and cls.__module__ == module.__name__
}


def _pack(value: object, depth: int = 0) -> WireValue:
    if depth > MAX_DEPTH:
        raise CacheMissError("cache graph exceeds maximum depth")
    if is_dataclass(value) and not isinstance(value, type):
        return {
            "$type": f"{type(value).__module__}.{type(value).__name__}",
            "fields": {f.name: _pack(getattr(value, f.name), depth + 1) for f in fields(value)},
        }
    if isinstance(value, Enum):
        return {"$enum": f"{type(value).__module__}.{type(value).__name__}", "value": value.value}
    if isinstance(value, FrozenMap):
        return {
            "$frozen_map": [
                [_pack(k, depth + 1), _pack(v, depth + 1)] for k, v in value.items_tuple()
            ]
        }
    if isinstance(value, tuple):
        return {"$tuple": [_pack(item, depth + 1) for item in value]}
    if isinstance(value, frozenset):
        return {"$frozenset": [_pack(item, depth + 1) for item in sorted(value, key=repr)]}
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    raise CacheMissError(f"unsupported cache value: {type(value).__name__}")


def _unpack(value: object, depth: int = 0, nodes: list[int] | None = None) -> object:
    nodes = [0] if nodes is None else nodes
    nodes[0] += 1
    if nodes[0] > MAX_NODES or depth > MAX_DEPTH:
        raise CacheMissError("cache graph exceeds limits")
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    if not isinstance(value, dict):
        raise CacheMissError("invalid cache node")
    if "$enum" in value:
        enum_name = value.get("$enum")
        enum = _ENUMS.get(enum_name) if isinstance(enum_name, str) else None
        if enum is None or set(value) != {"$enum", "value"}:
            raise CacheMissError("unknown cache enum")
        try:
            return enum(value["value"])
        except ValueError as exc:
            raise CacheMissError("invalid cache enum value") from exc
    if "$tuple" in value:
        items = value["$tuple"]
        if not isinstance(items, list):
            raise CacheMissError("invalid tuple node")
        return tuple(_unpack(item, depth + 1, nodes) for item in items)
    if "$frozenset" in value:
        items = value["$frozenset"]
        if not isinstance(items, list):
            raise CacheMissError("invalid frozenset node")
        return frozenset(_unpack(item, depth + 1, nodes) for item in items)
    if "$frozen_map" in value:
        items = value["$frozen_map"]
        if not isinstance(items, list):
            raise CacheMissError("invalid frozen map node")
        return FrozenMap(
            (_unpack(item[0], depth + 1, nodes), _unpack(item[1], depth + 1, nodes))
            for item in items
        )
    if (
        set(value) != {"$type", "fields"}
        or value["$type"] not in _TYPES
        or not isinstance(value["fields"], dict)
    ):
        raise CacheMissError("unknown cache type")
    cls = _TYPES[value["$type"]]
    expected = {f.name for f in fields(cls)}
    if set(value["fields"]) != expected:
        raise CacheMissError("cache fields do not match schema")
    return cls(**{f.name: _unpack(value["fields"][f.name], depth + 1, nodes) for f in fields(cls)})


def encode_module_result(result: ModuleAnalysisResult, metadata: CacheMetadata) -> bytes:
    payload = msgspec.msgpack.encode(
        {"schema": CACHE_SCHEMA_VERSION, "metadata": _pack(metadata), "result": _pack(result)}
    )
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise CacheMissError("cache payload exceeds maximum size")
    return payload


def decode_module_result(payload: bytes | bytearray | memoryview) -> CacheDecodeResult:
    try:
        if len(payload) > MAX_PAYLOAD_BYTES:
            raise CacheMissError("cache payload exceeds maximum size")
        body = msgspec.msgpack.decode(payload, type=dict, strict=True)
        if (
            not isinstance(body, dict)
            or set(body) != {"schema", "metadata", "result"}
            or body["schema"] != CACHE_SCHEMA_VERSION
        ):
            raise CacheMissError("unknown cache schema")
        metadata, result = _unpack(body["metadata"]), _unpack(body["result"])
        if not isinstance(metadata, CacheMetadata) or not isinstance(result, ModuleAnalysisResult):
            raise CacheMissError("invalid cache root")
        return CacheDecodeResult(result, metadata)
    except (
        CacheMissError,
        msgspec.DecodeError,
        msgspec.ValidationError,
        TypeError,
        ValueError,
    ) as exc:
        return CacheDecodeResult(None, None, str(exc))
