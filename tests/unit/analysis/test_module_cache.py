from tests.utils.builders import make_source

from taut.analysis.contracts import AdapterIdentity
from taut.analysis.module_cache import (
    CacheErrorCode,
    CacheMetadata,
    decode_module_result,
    encode_module_result,
)
from taut.analysis.python.language_adapter import PythonAstAdapter
from taut.domain.facts import ResolutionState


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
