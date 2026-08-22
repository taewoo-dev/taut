"""Authenticated fast cache payloads for trusted pytaut-produced domain objects.

Pickle is never accepted on authenticity alone: payloads are bound to their full
cache key with a user-private secret, versioned for the running interpreter, and
loaded through a closed module whitelist. Any uncertainty is a cache miss.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import os
import pickle
import secrets
import stat
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Final

from taut.analysis.contracts import ModuleAnalysisResult

MAGIC: Final = b"TAUTPKL1"
KEY_BYTES: Final = 32
MAX_PAYLOAD_BYTES: Final = 256 * 1024 * 1024
_HEADER_BYTES: Final = len(MAGIC) + 2 + hashlib.sha256().digest_size
_ALLOWED_MODULES: Final = frozenset(
    {
        "taut.analysis.contracts",
        "taut.domain.analysis_state",
        "taut.domain.facts",
        "taut.domain.frozen",
        "taut.domain.ids",
        "taut.domain.issues",
        "taut.domain.location",
        "taut.domain.provenance",
        "taut.domain.relations",
    }
)


@dataclass(frozen=True)
class ModuleBundle:
    entries: tuple[tuple[str, str, ModuleAnalysisResult], ...]


class _DomainUnpickler(pickle.Unpickler):
    def find_class(self, module: str, name: str) -> object:
        own_bundle = module == __name__ and name == "ModuleBundle"
        if not own_bundle and (module not in _ALLOWED_MODULES or name.startswith("_")):
            raise pickle.UnpicklingError(f"cache type is not allowed: {module}.{name}")
        value = super().find_class(module, name)
        if not isinstance(value, type):
            raise pickle.UnpicklingError(f"cache global is not a type: {module}.{name}")
        return value


def encode_authenticated_module(
    result: ModuleAnalysisResult, *, context: bytes, signing_key: bytes
) -> bytes:
    return _encode_authenticated(result, context=context, signing_key=signing_key)


def encode_authenticated_bundle(
    bundle: ModuleBundle, *, context: bytes, signing_key: bytes
) -> bytes:
    return _encode_authenticated(bundle, context=context, signing_key=signing_key)


def decode_authenticated_module(
    payload: bytes, *, context: bytes, signing_key: bytes
) -> ModuleAnalysisResult | None:
    try:
        value = _decode_authenticated(payload, context=context, signing_key=signing_key)
        if type(value) is not ModuleAnalysisResult:
            return None
        return value
    except (OSError, ValueError, TypeError):
        return None


def decode_authenticated_bundle(
    payload: bytes, *, context: bytes, signing_key: bytes
) -> ModuleBundle | None:
    try:
        value = _decode_authenticated(payload, context=context, signing_key=signing_key)
        return value if type(value) is ModuleBundle else None
    except (OSError, ValueError, TypeError):
        return None


def _encode_authenticated(value: object, *, context: bytes, signing_key: bytes) -> bytes:
    _validate_key(signing_key)
    body = pickle.dumps(value, protocol=5)
    version = bytes((sys.version_info.major, sys.version_info.minor))
    signature = hmac.digest(signing_key, MAGIC + version + context + body, "sha256")
    payload = MAGIC + version + signature + body
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError("authenticated cache payload exceeds maximum size")
    return payload


def _decode_authenticated(payload: bytes, *, context: bytes, signing_key: bytes) -> object:
    _validate_key(signing_key)
    if len(payload) < _HEADER_BYTES or len(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError("authenticated cache payload size is invalid")
    if payload[: len(MAGIC)] != MAGIC:
        raise ValueError("authenticated cache magic is invalid")
    version = payload[len(MAGIC) : len(MAGIC) + 2]
    if version != bytes((sys.version_info.major, sys.version_info.minor)):
        raise ValueError("authenticated cache interpreter version is invalid")
    signature_start = len(MAGIC) + 2
    signature_end = signature_start + hashlib.sha256().digest_size
    signature = payload[signature_start:signature_end]
    body = payload[signature_end:]
    expected = hmac.digest(signing_key, MAGIC + version + context + body, "sha256")
    if not hmac.compare_digest(signature, expected):
        raise ValueError("authenticated cache signature is invalid")
    try:
        return _DomainUnpickler(io.BytesIO(body)).load()
    except (ImportError, pickle.PickleError, EOFError) as error:
        raise ValueError("authenticated cache payload is invalid") from error


def cache_signing_context(parts: tuple[str, ...]) -> bytes:
    encoded = tuple(part.encode("utf-8") for part in parts)
    return b"".join(len(part).to_bytes(8, "big") + part for part in encoded)


@lru_cache(maxsize=1)
def load_user_signing_key() -> bytes | None:
    """Load or create a private key outside project-controlled cache directories."""
    try:
        path = _signing_key_path()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name != "nt":
            path.parent.chmod(0o700)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            try:
                os.write(descriptor, secrets.token_bytes(KEY_BYTES))
            finally:
                os.close(descriptor)
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            return None
        if os.name != "nt" and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
            return None
        key = path.read_bytes()
        return key if len(key) == KEY_BYTES else None
    except (OSError, RuntimeError):
        return None


def _signing_key_path() -> Path:
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    elif os.name == "nt":
        base = Path.home() / "AppData" / "Local"
    else:
        base = Path.home() / ".cache"
    return base / "taut" / "cache-signing.key"


def _validate_key(signing_key: bytes) -> None:
    if len(signing_key) != KEY_BYTES:
        raise ValueError("cache signing key must be 32 bytes")
