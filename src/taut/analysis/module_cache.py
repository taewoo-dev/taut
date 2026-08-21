"""Compact direct MessagePack codec for module analysis results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, cast

import msgspec

from taut.analysis.contracts import AdapterIdentity, ModuleAnalysisResult
from taut.domain.facts import ModuleFacts
from taut.domain.frozen import FrozenMap
from taut.domain.issues import CacheErrorCode, EngineIssue, EngineIssueKind
from taut.domain.location import ConfigLocation, ConfigPath, ProjectPath, SourceRange
from taut.domain.relations import ModuleRelations

CACHE_SCHEMA_VERSION = 2
MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_NODES = 10_000_000
MAX_DEPTH = 1024


@dataclass(frozen=True)
class CacheMetadata:
    adapter: AdapterIdentity
    resolver_identity: str


class SourceIssueLocation(msgspec.Struct, tag="source", tag_field="tag", array_like=True):
    path: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int


class ConfigIssueLocation(msgspec.Struct, tag="config", tag_field="tag", array_like=True):
    path_kind: Literal["project", "config"]
    path: str
    line: int | None
    column: int | None


IssueLocationWire = SourceIssueLocation | ConfigIssueLocation | None


class IssueWire(msgspec.Struct, array_like=True):
    code: str
    kind: EngineIssueKind
    message: str
    location: IssueLocationWire
    cause: str | None
    retryable: bool


class CacheEnvelope(msgspec.Struct, array_like=True):
    schema: int
    metadata: CacheMetadata
    facts: ModuleFacts
    issues: tuple[IssueWire, ...]
    relations: ModuleRelations


@dataclass(frozen=True)
class CacheDecodeResult:
    value: ModuleAnalysisResult | None
    metadata: CacheMetadata | None
    error_code: CacheErrorCode | None = None
    error: str | None = None


def _enc_hook(value: object) -> object:
    if isinstance(value, FrozenMap):
        return cast(tuple[tuple[object, object], ...], value.items_tuple())
    return msgspec.NODEFAULT


def _dec_hook(target: type[Any], value: object) -> object:
    if (getattr(target, "__origin__", None) is FrozenMap or target is FrozenMap) and isinstance(
        value, (list, tuple)
    ):
        return FrozenMap(
            cast(list[tuple[object, object]] | tuple[tuple[object, object], ...], value)
        )
    return msgspec.NODEFAULT


_DECODER = msgspec.msgpack.Decoder(CacheEnvelope, dec_hook=_dec_hook)


def _issue_wire(issue: EngineIssue) -> IssueWire:
    location: IssueLocationWire
    if issue.location is None:
        location = None
    elif isinstance(issue.location, SourceRange):
        location = SourceIssueLocation(
            issue.location.path.value,
            issue.location.start_line,
            issue.location.start_column,
            issue.location.end_line,
            issue.location.end_column,
        )
    else:
        path = issue.location.path
        location = ConfigIssueLocation(
            "project" if isinstance(path, ProjectPath) else "config",
            path.value,
            issue.location.line,
            issue.location.column,
        )
    return IssueWire(issue.code, issue.kind, issue.message, location, issue.cause, issue.retryable)


def _issue(wire: IssueWire) -> EngineIssue:
    location: SourceRange | ConfigLocation | None
    if wire.location is None:
        location = None
    elif isinstance(wire.location, SourceIssueLocation):
        location = SourceRange(
            ProjectPath(wire.location.path),
            wire.location.start_line,
            wire.location.start_column,
            wire.location.end_line,
            wire.location.end_column,
        )
    else:
        path = (
            ProjectPath(wire.location.path)
            if wire.location.path_kind == "project"
            else ConfigPath(wire.location.path)
        )
        location = ConfigLocation(path, wire.location.line, wire.location.column)
    return EngineIssue(wire.code, wire.kind, wire.message, location, wire.cause, wire.retryable)


def encode_module_result(result: ModuleAnalysisResult, metadata: CacheMetadata) -> bytes:
    envelope = CacheEnvelope(
        CACHE_SCHEMA_VERSION,
        metadata,
        result.facts,
        tuple(_issue_wire(issue) for issue in result.issues),
        result.relations,
    )
    payload = msgspec.msgpack.encode(envelope, enc_hook=_enc_hook)
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError("cache payload exceeds maximum size")
    return payload


def decode_module_result(payload: bytes | bytearray | memoryview) -> CacheDecodeResult:
    try:
        if len(payload) > MAX_PAYLOAD_BYTES:
            raise ValueError("cache payload exceeds maximum size")
        envelope = _DECODER.decode(payload)
        if envelope.schema != CACHE_SCHEMA_VERSION:
            raise ValueError("unknown cache schema")
        result = ModuleAnalysisResult(
            envelope.facts,
            tuple(_issue(issue) for issue in envelope.issues),
            envelope.relations,
        )
        return CacheDecodeResult(result, envelope.metadata)
    except Exception as exc:
        return CacheDecodeResult(
            None,
            None,
            CacheErrorCode.LIMIT if "maximum" in str(exc) else CacheErrorCode.DECODE,
            str(exc),
        )
