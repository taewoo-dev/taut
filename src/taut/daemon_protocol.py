"""Strict wire contracts and bounded framing for the local daemon."""

from __future__ import annotations

import socket
import struct

import msgspec

from taut import __version__

PROTOCOL_VERSION = 1
STATUS_SCHEMA_VERSION = 2
MAX_REQUEST_SIZE = 64 * 1024
MAX_RESPONSE_SIZE = 32 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 300.0


class CheckWire(msgspec.Struct, forbid_unknown_fields=True, frozen=True):
    config_path: str | None = None
    output_format: str = "text"
    show_inactive: bool = False
    verbose: bool = False
    use_color: bool = False
    width: int = 100


class DaemonRequest(msgspec.Struct, forbid_unknown_fields=True, frozen=True):
    action: str
    token: str
    root: str
    protocol: int = PROTOCOL_VERSION
    taut_version: str = __version__
    check: CheckWire | None = None


class TimingWire(msgspec.Struct, forbid_unknown_fields=True, frozen=True):
    name: str
    milliseconds: float


class CountersWire(msgspec.Struct, forbid_unknown_fields=True, frozen=True):
    reparsed_modules: int = 0
    reused_modules: int = 0
    recomputed_providers: int = 0
    reused_providers: int = 0
    recomputed_evaluations: int = 0
    reused_evaluations: int = 0
    full_policy_rerun: bool = False


class DaemonResponse(msgspec.Struct, forbid_unknown_fields=True, frozen=True):
    ok: bool
    stdout: bytes = b""
    stderr: bytes = b""
    exit_code: int = 2
    error: str | None = None
    timings: tuple[TimingWire, ...] = ()
    counters: CountersWire = CountersWire()


_REQUEST_DECODER = msgspec.msgpack.Decoder(DaemonRequest, strict=True)
_RESPONSE_DECODER = msgspec.msgpack.Decoder(DaemonResponse, strict=True)


def encode_frame(value: object, *, maximum: int) -> bytes:
    payload = msgspec.msgpack.encode(value)
    if not payload or len(payload) > maximum:
        raise ValueError("frame size is outside the allowed range")
    return struct.pack(">I", len(payload)) + payload


def receive_frame(sock: socket.socket, *, maximum: int) -> bytes:
    size = struct.unpack(">I", receive_exact(sock, 4))[0]
    if size == 0 or size > maximum:
        raise ValueError("frame size is outside the allowed range")
    return receive_exact(sock, size)


def receive_exact(sock: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise ConnectionError("connection closed before frame completed")
        result.extend(chunk)
    return bytes(result)


def send_request(sock: socket.socket, request: DaemonRequest) -> None:
    sock.sendall(encode_frame(request, maximum=MAX_REQUEST_SIZE))


def receive_request(sock: socket.socket) -> DaemonRequest:
    return _REQUEST_DECODER.decode(receive_frame(sock, maximum=MAX_REQUEST_SIZE))


def send_response(sock: socket.socket, response: DaemonResponse) -> None:
    sock.sendall(encode_frame(response, maximum=MAX_RESPONSE_SIZE))


def receive_response(sock: socket.socket) -> DaemonResponse:
    return _RESPONSE_DECODER.decode(receive_frame(sock, maximum=MAX_RESPONSE_SIZE))
