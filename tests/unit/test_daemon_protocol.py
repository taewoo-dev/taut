from __future__ import annotations

import socket
import struct
import threading

import msgspec
import pytest

from taut.daemon_protocol import (
    MAX_REQUEST_SIZE,
    DaemonRequest,
    encode_frame,
    receive_frame,
    receive_request,
)


def test_receive_frame_accepts_partial_delivery() -> None:
    receiving, sending = socket.socketpair()
    frame = encode_frame(DaemonRequest("ping", "x" * 32, "/project"), maximum=MAX_REQUEST_SIZE)

    def transmit() -> None:
        with sending:
            for byte in frame:
                sending.sendall(bytes((byte,)))

    thread = threading.Thread(target=transmit)
    thread.start()
    with receiving:
        payload = receive_frame(receiving, maximum=MAX_REQUEST_SIZE)
    thread.join()

    request = msgspec.msgpack.decode(payload, type=DaemonRequest, strict=True)
    assert request.action == "ping"


def test_receive_frame_preserves_coalesced_frames() -> None:
    receiving, sending = socket.socketpair()
    first = encode_frame(DaemonRequest("ping", "a" * 32, "/one"), maximum=MAX_REQUEST_SIZE)
    second = encode_frame(DaemonRequest("stop", "b" * 32, "/two"), maximum=MAX_REQUEST_SIZE)
    with sending:
        sending.sendall(first + second)
    with receiving:
        one = msgspec.msgpack.decode(
            receive_frame(receiving, maximum=MAX_REQUEST_SIZE), type=DaemonRequest
        )
        two = msgspec.msgpack.decode(
            receive_frame(receiving, maximum=MAX_REQUEST_SIZE), type=DaemonRequest
        )
    assert (one.action, two.action) == ("ping", "stop")


@pytest.mark.parametrize("size", [0, MAX_REQUEST_SIZE + 1])
def test_receive_frame_rejects_invalid_size(size: int) -> None:
    receiving, sending = socket.socketpair()
    with sending:
        sending.sendall(struct.pack(">I", size))
    with receiving, pytest.raises(ValueError, match="frame size"):
        receive_frame(receiving, maximum=MAX_REQUEST_SIZE)


def test_receive_frame_rejects_truncated_payload() -> None:
    receiving, sending = socket.socketpair()
    with sending:
        sending.sendall(struct.pack(">I", 4) + b"x")
    with receiving, pytest.raises(ConnectionError, match="closed"):
        receive_frame(receiving, maximum=MAX_REQUEST_SIZE)


def test_receive_request_rejects_malformed_or_unknown_fields() -> None:
    for payload in (
        b"not-msgpack",
        msgspec.msgpack.encode(
            {"action": "ping", "token": "x" * 32, "root": "/x", "unknown": True}
        ),
    ):
        receiving, sending = socket.socketpair()
        with sending:
            sending.sendall(struct.pack(">I", len(payload)) + payload)
        with receiving, pytest.raises(msgspec.DecodeError):
            receive_request(receiving)
