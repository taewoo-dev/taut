"""Integrity and authentication envelope for rendered report cache entries."""

from __future__ import annotations

import hashlib
import hmac

_CHECKSUM_MAGIC = b"RPT1"
_AUTHENTICATED_MAGIC = b"RPA2"
_HEADER_BYTES = 36


def encode_report(payload: bytes, fingerprint: str, signing_key: bytes | None) -> bytes:
    if signing_key is None:
        return _CHECKSUM_MAGIC + hashlib.sha256(payload).digest() + payload
    signature = hmac.digest(signing_key, fingerprint.encode() + payload, "sha256")
    return _AUTHENTICATED_MAGIC + signature + payload


def decode_report(
    value: bytes,
    fingerprint: str,
    signing_key: bytes | None,
) -> bytes | None:
    if len(value) < _HEADER_BYTES:
        return None
    signature = value[4:_HEADER_BYTES]
    payload = value[_HEADER_BYTES:]
    if signing_key is None:
        valid = value[:4] == _CHECKSUM_MAGIC and hmac.compare_digest(
            signature,
            hashlib.sha256(payload).digest(),
        )
    else:
        expected = hmac.digest(signing_key, fingerprint.encode() + payload, "sha256")
        valid = value[:4] == _AUTHENTICATED_MAGIC and hmac.compare_digest(signature, expected)
    return payload if valid else None
