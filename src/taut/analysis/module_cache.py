"""Strict tagged MessagePack module cache."""

from __future__ import annotations

import dataclasses
import zlib
from dataclasses import fields, is_dataclass
from enum import Enum
from typing import cast

import msgspec

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
from taut.domain.issues import CacheErrorCode

CACHE_SCHEMA_VERSION = 1
MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_NODES = 10_000_000
MAX_DEPTH = 1024


@dataclasses.dataclass(frozen=True)
class CacheMetadata:
    adapter: AdapterIdentity
    resolver_identity: str


@dataclasses.dataclass(frozen=True)
class CacheDecodeResult:
    value: ModuleAnalysisResult | None
    metadata: CacheMetadata | None
    error_code: CacheErrorCode | None = None
    error: str | None = None


class DataclassNode(msgspec.Struct, tag="dataclass", tag_field="kind", forbid_unknown_fields=True):
    type_id: str
    fields: tuple[tuple[str, WireValue], ...]


class EnumNode(msgspec.Struct, tag="enum", tag_field="kind", forbid_unknown_fields=True):
    type_id: str
    value: str


class TupleNode(msgspec.Struct, tag="tuple", tag_field="kind", forbid_unknown_fields=True):
    items: tuple[WireValue, ...]


class FrozenSetNode(msgspec.Struct, tag="frozenset", tag_field="kind", forbid_unknown_fields=True):
    items: tuple[WireValue, ...]


class FrozenMapNode(msgspec.Struct, tag="frozen_map", tag_field="kind", forbid_unknown_fields=True):
    items: tuple[tuple[WireValue, WireValue], ...]


type WireValue = (
    str | DataclassNode | EnumNode | TupleNode | FrozenSetNode | FrozenMapNode | int | bool | None
)


class CacheEnvelope(msgspec.Struct, forbid_unknown_fields=True):
    schema: int
    metadata: DataclassNode
    result: DataclassNode


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
_TYPES = {
    f"{c.__module__}.{c.__name__}": c
    for m in _MODULES
    for c in vars(m).values()
    if isinstance(c, type) and is_dataclass(c) and c.__module__ == m.__name__
}
_TYPES[f"{CacheMetadata.__module__}.{CacheMetadata.__name__}"] = CacheMetadata
_ENUMS = {
    f"{c.__module__}.{c.__name__}": c
    for m in _MODULES
    for c in vars(m).values()
    if isinstance(c, type) and issubclass(c, Enum) and c.__module__ == m.__name__
}
_DECODER = msgspec.msgpack.Decoder(CacheEnvelope)


def _pack(v: object, d: int = 0, n: list[int] | None = None) -> WireValue:
    n = [0] if n is None else n
    n[0] += 1
    if d > MAX_DEPTH or n[0] > MAX_NODES:
        raise ValueError("cache graph exceeds limits")
    if isinstance(v, Enum):
        return EnumNode(f"{type(v).__module__}.{type(v).__name__}", str(v.value))
    if v is None or isinstance(v, (str, bool, int)):
        return v
    if is_dataclass(v) and not isinstance(v, type):
        return DataclassNode(
            f"{type(v).__module__}.{type(v).__name__}",
            tuple((f.name, _pack(getattr(v, f.name), d + 1, n)) for f in fields(v)),
        )
    if isinstance(v, FrozenMap):
        items = cast(tuple[tuple[object, object], ...], v.items_tuple())
        return FrozenMapNode(tuple((_pack(k, d + 1, n), _pack(x, d + 1, n)) for k, x in items))
    if isinstance(v, tuple):
        return TupleNode(tuple(_pack(x, d + 1, n) for x in cast(tuple[object, ...], v)))
    if isinstance(v, frozenset):
        return FrozenSetNode(
            tuple(_pack(x, d + 1, n) for x in sorted(cast(frozenset[object], v), key=repr)),
        )
    raise TypeError(type(v).__name__)


def _unpack(v: WireValue, d: int = 0, n: list[int] | None = None) -> object:
    n = [0] if n is None else n
    n[0] += 1
    if d > MAX_DEPTH or n[0] > MAX_NODES:
        raise ValueError("cache graph exceeds limits")
    if v is None or isinstance(v, (str, int, bool)):
        return v
    if isinstance(v, EnumNode):
        e = _ENUMS.get(v.type_id)
        if e is None:
            raise TypeError("unknown cache enum")
        return e(v.value)
    if isinstance(v, TupleNode):
        return tuple(_unpack(x, d + 1, n) for x in v.items)
    if isinstance(v, FrozenSetNode):
        return frozenset(_unpack(x, d + 1, n) for x in v.items)
    if isinstance(v, FrozenMapNode):
        return FrozenMap((_unpack(k, d + 1, n), _unpack(x, d + 1, n)) for k, x in v.items)
    c = _TYPES.get(v.type_id)
    if c is None:
        raise TypeError("unknown cache dataclass")
    expected = tuple(f.name for f in fields(c))
    if tuple(k for k, _ in v.fields) != expected:
        raise TypeError("cache fields mismatch")
    return c(**{k: _unpack(x, d + 1, n) for k, x in v.fields})


def encode_module_result(result: ModuleAnalysisResult, metadata: CacheMetadata) -> bytes:
    raw = msgspec.msgpack.encode(
        CacheEnvelope(
            CACHE_SCHEMA_VERSION,
            cast(DataclassNode, _pack(metadata)),
            cast(DataclassNode, _pack(result)),
        )
    )
    p = zlib.compress(raw, level=6)
    if len(p) > MAX_PAYLOAD_BYTES:
        raise ValueError("cache payload exceeds maximum size")
    return p


def decode_module_result(payload: bytes | bytearray | memoryview) -> CacheDecodeResult:
    try:
        if len(payload) > MAX_PAYLOAD_BYTES:
            raise ValueError("cache payload exceeds maximum size")
        raw = zlib.decompress(payload, bufsize=MAX_PAYLOAD_BYTES)
        if len(raw) > MAX_PAYLOAD_BYTES:
            raise ValueError("cache payload exceeds maximum size")
        e = _DECODER.decode(raw)
        if e.schema != CACHE_SCHEMA_VERSION:
            raise ValueError("unknown cache schema")
        m, r = _unpack(e.metadata), _unpack(e.result)
        if not isinstance(m, CacheMetadata) or not isinstance(r, ModuleAnalysisResult):
            raise TypeError("invalid cache root")
        return CacheDecodeResult(r, m)
    except Exception as exc:
        return CacheDecodeResult(
            None,
            None,
            CacheErrorCode.LIMIT
            if "maximum" in str(exc) or "limits" in str(exc)
            else CacheErrorCode.DECODE,
            str(exc),
        )
