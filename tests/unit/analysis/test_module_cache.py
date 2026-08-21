import random

from tests.utils.builders import make_source

from taut.analysis.contracts import AdapterIdentity
from taut.analysis.module_cache import (
    CacheMetadata,
    decode_module_result,
    encode_module_result,
)
from taut.analysis.python.language_adapter import PythonAstAdapter
from taut.domain.facts import ResolutionState
from taut.domain.issues import CacheErrorCode


def test_module_cache_roundtrip_preserves_domain_and_strenum_types() -> None:
    result = PythonAstAdapter().analyze_module(
        make_source(
            "app/model.py",
            "from pydantic import BaseModel\nclass Model(BaseModel):\n    value: int",
        )
    )
    metadata = CacheMetadata(AdapterIdentity("python", "1"), "resolver-1")
    payload = encode_module_result(result, metadata)
    decoded = decode_module_result(payload)
    assert decoded.value == result
    assert decoded.metadata == metadata
    assert encode_module_result(result, metadata) == payload
    assert ResolutionState.RESOLVED.value == "resolved"


def test_module_cache_malformed_payload_is_typed_miss() -> None:
    decoded = decode_module_result(b"\x81\xa6schema\x01")
    assert decoded.value is None
    assert decoded.error_code is CacheErrorCode.DECODE


def test_module_cache_short_random_bytes_never_raise() -> None:
    randomizer = random.Random(7)
    for size in range(64):
        payload = bytes(randomizer.randrange(256) for _ in range(size))
        decoded = decode_module_result(payload)
        assert decoded.value is None
        assert decoded.error_code is not None


def test_module_cache_schema_and_size_misses_are_typed() -> None:
    result = PythonAstAdapter().analyze_module(make_source("a.py", "value = 1"))
    metadata = CacheMetadata(AdapterIdentity("python", "1"), "resolver-1")
    payload = bytearray(encode_module_result(result, metadata))
    payload[0] = 0x81
    assert decode_module_result(payload).error_code is CacheErrorCode.DECODE
    assert (
        decode_module_result(payload + b"x" * (8 * 1024 * 1024)).error_code is CacheErrorCode.LIMIT
    )
