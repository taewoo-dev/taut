from __future__ import annotations

import dataclasses

# Test-only SQL corruption uses the store's private connection deliberately.
# pyright: reportPrivateUsage=false
import hashlib
import hmac
import io
import pickle
import sys
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import msgspec
import pytest
from tests.utils.builders import make_source

from taut.analysis import module_cache
from taut.analysis.contracts import AdapterIdentity, ModuleAnalysisResult
from taut.analysis.python.language_adapter import PythonAstAdapter
from taut.cache import authenticated
from taut.cache.authenticated import (
    MAGIC,
    ModuleBundle,
    cache_signing_context,
    decode_authenticated_bundle,
    decode_authenticated_module,
    encode_authenticated_bundle,
    encode_authenticated_module,
)
from taut.cache.store import MAX_AGE_SECONDS, CacheKey, CacheStore
from taut.domain import facts
from taut.domain.issues import EngineIssue, EngineIssueKind
from taut.domain.location import ConfigLocation, ConfigPath, ProjectPath, SourceRange

HASH = hashlib.sha256(b"source").hexdigest()


def _key(suffix: str = "") -> CacheKey:
    return CacheKey(HASH, AdapterIdentity("python", "1"), "resolver" + suffix)


def _result() -> ModuleAnalysisResult:
    return PythonAstAdapter().analyze_module(make_source("app/a.py", "value = 1"))


def _rich_result() -> ModuleAnalysisResult:
    base = _result()
    issues = (
        EngineIssue("A", EngineIssueKind.PARSE_FAILURE, "bad", None),
        EngineIssue(
            "B",
            EngineIssueKind.ANALYSIS_FAILURE,
            "bad",
            SourceRange(ProjectPath("a.py"), 0, 0, 0, 1),
        ),
        EngineIssue(
            "C", EngineIssueKind.RULE_FAILURE, "bad", ConfigLocation(ProjectPath("a.py"), 1, 2)
        ),
        EngineIssue(
            "D",
            EngineIssueKind.RULE_FAILURE,
            "bad",
            ConfigLocation(ConfigPath("cfg.toml"), None, None),
        ),
    )
    return dataclasses.replace(base, issues=issues)


def test_key_validation_and_paths(tmp_path: Path) -> None:
    assert CacheStore(tmp_path).path == tmp_path / "cache.sqlite3"
    with pytest.raises(ValueError):
        CacheKey("x", AdapterIdentity("python", "1"), "resolver")
    with pytest.raises(ValueError):
        CacheKey("A" * 64, AdapterIdentity("python", "1"), "resolver")
    with pytest.raises(ValueError):
        CacheKey(HASH, AdapterIdentity("", "1"), "resolver")
    with pytest.raises(ValueError):
        CacheKey(HASH, AdapterIdentity("python", ""), "resolver")
    with pytest.raises(ValueError):
        CacheKey(HASH, AdapterIdentity("python", "1"), "")
    with pytest.raises(RuntimeError):
        CacheStore(tmp_path).stats()


def test_module_hit_miss_invalidation_corruption_and_access(tmp_path: Path) -> None:
    result = _result()
    with CacheStore(tmp_path) as store:
        assert store.get_module(_key()) is None
        store.put_module(_key(), result)
        assert store.get_module(_key()) == result
        assert store.get_module(CacheKey(HASH, AdapterIdentity("python", "2"), "resolver")) is None
        assert store.get_module(_key("-changed")) is None
        store._conn().execute("UPDATE module_entries SET payload=?", (b"bad",))
        assert store.get_module(_key()) is None
        assert store.stats().module_entries == 0


def test_authenticated_module_cache_is_key_bound_and_restricted() -> None:
    signing_key = b"k" * 32
    context = cache_signing_context(("source", "python", "1", "resolver", "app.a"))
    payload = encode_authenticated_module(_rich_result(), context=context, signing_key=signing_key)
    assert (
        decode_authenticated_module(payload, context=context, signing_key=signing_key)
        == _rich_result()
    )
    assert (
        decode_authenticated_module(payload + b"x", context=context, signing_key=signing_key)
        is None
    )
    assert (
        decode_authenticated_module(
            payload,
            context=cache_signing_context(("different",)),
            signing_key=signing_key,
        )
        is None
    )
    assert decode_authenticated_module(payload, context=context, signing_key=b"x" * 32) is None
    assert decode_authenticated_module(b"", context=context, signing_key=signing_key) is None
    assert (
        decode_authenticated_module(
            b"BADMAGIC" + payload[len(MAGIC) :],
            context=context,
            signing_key=signing_key,
        )
        is None
    )
    version_offset = len(MAGIC)
    wrong_version = payload[:version_offset] + b"\x00\x00" + payload[version_offset + 2 :]
    assert (
        decode_authenticated_module(wrong_version, context=context, signing_key=signing_key) is None
    )
    bundle_payload = encode_authenticated_bundle(
        ModuleBundle((("app.a", HASH, _result()),)),
        context=context,
        signing_key=signing_key,
    )
    assert (
        decode_authenticated_module(bundle_payload, context=context, signing_key=signing_key)
        is None
    )
    assert decode_authenticated_bundle(payload, context=context, signing_key=signing_key) is None
    with pytest.raises(ValueError):
        encode_authenticated_module(_result(), context=context, signing_key=b"short")

    class UntrustedGlobal:
        def __reduce__(self) -> tuple[object, tuple[str]]:
            return (eval, ("1 + 1",))

    body = pickle.dumps(UntrustedGlobal(), protocol=5)
    version = bytes((sys.version_info.major, sys.version_info.minor))
    signature = hmac.digest(signing_key, MAGIC + version + context + body, "sha256")
    assert (
        decode_authenticated_module(
            MAGIC + version + signature + body,
            context=context,
            signing_key=signing_key,
        )
        is None
    )


def test_authenticated_store_separates_identical_content_by_module(tmp_path: Path) -> None:
    signing_key = b"s" * 32
    adapter = AdapterIdentity("python", "1")
    first = PythonAstAdapter().analyze_module(make_source("app/a.py", "value = 1"))
    second = PythonAstAdapter().analyze_module(make_source("app/b.py", "value = 1"))
    first_key = CacheKey(HASH, adapter, "resolver", "app.a")
    second_key = CacheKey(HASH, adapter, "resolver", "app.b")
    with CacheStore(tmp_path, signing_key=signing_key) as store:
        assert store.put_modules(((first_key, first), (second_key, second)))
        assert store.get_modules((first_key, second_key)) == (first, second)
        assert store.stats().module_entries == 2
    with CacheStore(tmp_path, signing_key=b"w" * 32) as store:
        assert store.get_modules((first_key, second_key)) == (None, None)


def test_authenticated_bundle_stats_context_and_cleanup(tmp_path: Path) -> None:
    signing_key = b"b" * 32
    bundle_key = hashlib.sha256(b"bundle").hexdigest()
    context = cache_signing_context(("project", "resolver"))
    bundle = ModuleBundle((("app.a", HASH, _result()),))
    with CacheStore(tmp_path, signing_key=signing_key) as store:
        assert store.get_module_bundle(bundle_key, context=context) is None
        assert not store.put_module_bundle("bad", bundle, context=context)
        assert store.get_module_bundle("bad", context=context) is None
        assert store.put_module_bundle(bundle_key, bundle, context=context)
        assert store.get_module_bundle(bundle_key, context=context) == bundle
        assert store.stats().module_entries == 1
        assert store.get_module_bundle(bundle_key, context=b"wrong") is None
        assert store.stats().module_entries == 0


def test_user_signing_key_requires_private_regular_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_path = tmp_path / "state" / "cache-signing.key"
    monkeypatch.setattr(authenticated, "_signing_key_path", lambda: key_path)
    authenticated.load_user_signing_key.cache_clear()
    try:
        first = authenticated.load_user_signing_key()
        assert first is not None and len(first) == authenticated.KEY_BYTES
        assert key_path.stat().st_mode & 0o077 == 0
        key_path.chmod(0o644)
        authenticated.load_user_signing_key.cache_clear()
        assert authenticated.load_user_signing_key() is None
        key_path.unlink()
        target = tmp_path / "target-key"
        target.write_bytes(b"x" * authenticated.KEY_BYTES)
        key_path.symlink_to(target)
        authenticated.load_user_signing_key.cache_clear()
        assert authenticated.load_user_signing_key() is None
        key_path.unlink()
        key_path.write_bytes(b"short")
        authenticated.load_user_signing_key.cache_clear()
        assert authenticated.load_user_signing_key() is None
        blocked_parent = tmp_path / "blocked"
        blocked_parent.write_text("not a directory")
        monkeypatch.setattr(authenticated, "_signing_key_path", lambda: blocked_parent / "key")
        authenticated.load_user_signing_key.cache_clear()
        assert authenticated.load_user_signing_key() is None
    finally:
        authenticated.load_user_signing_key.cache_clear()


def test_authenticated_payload_size_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(authenticated, "MAX_PAYLOAD_BYTES", 1)
    with pytest.raises(ValueError):
        encode_authenticated_module(_result(), context=b"context", signing_key=b"k" * 32)
    with CacheStore(tmp_path, signing_key=b"k" * 32) as store:
        assert not store.put_module_bundle(
            hashlib.sha256(b"bundle-limit").hexdigest(),
            ModuleBundle((("app.a", HASH, _result()),)),
            context=b"context",
        )


def test_authenticated_unpickler_rejects_allowed_module_non_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(facts, "NotACacheType", 1, raising=False)
    unpickler = authenticated._DomainUnpickler(io.BytesIO(b""))
    with pytest.raises(pickle.UnpicklingError):
        unpickler.find_class("taut.domain.facts", "NotACacheType")


def test_report_checksum_and_stats(tmp_path: Path) -> None:
    fingerprint = hashlib.sha256(b"report").hexdigest()
    with CacheStore(tmp_path) as store:
        assert store.get_report(fingerprint) is None
        store.put_report(fingerprint, b"report-data")
        assert store.get_report(fingerprint) == b"report-data"
        store._conn().execute("UPDATE report_entries SET payload=?", (b"tampered",))
        assert store.get_report(fingerprint) is None
        assert store.stats().report_entries == 0
        with pytest.raises(ValueError):
            store.put_report("bad", b"x")


def test_schema_and_database_corruption_quarantine(tmp_path: Path) -> None:
    with CacheStore(tmp_path) as store:
        store._conn().execute("UPDATE cache_meta SET value='999' WHERE key='schema'")
    with CacheStore(tmp_path) as store:
        assert store.stats().total_bytes == 0
    path = tmp_path / "cache.sqlite3"
    path.write_bytes(b"not sqlite")
    with CacheStore(tmp_path) as store:
        assert store.stats().total_bytes == 0
    assert list(tmp_path.glob("cache.sqlite3.corrupt.*"))


def test_rollback_and_cleanup_age_size(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result = _result()
    with CacheStore(tmp_path) as store:

        def fail(_conn: object) -> None:
            raise RuntimeError("boom")

        monkeypatch.setattr(store, "_cleanup", fail)
        with pytest.raises(RuntimeError):
            store.put_module(_key(), result)
        assert store.stats().module_entries == 0

        def noop(_conn: object) -> None:
            return None

        monkeypatch.setattr(store, "_cleanup", noop)
        store.put_module(_key(), result)
        monkeypatch.undo()
        now = time.time()
        store._conn().execute("UPDATE module_entries SET accessed=?", (now - MAX_AGE_SECONDS - 1,))
        store._cleanup(store._conn())
        assert store.stats().module_entries == 0


def test_concurrent_independent_stores(tmp_path: Path) -> None:
    result = _result()

    def write(index: int) -> bool:
        with CacheStore(tmp_path) as store:
            store.put_module(_key(str(index)), result)
            return store.get_module(_key(str(index))) == result

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(pool.map(write, range(4)))
    with CacheStore(tmp_path) as store:
        assert store.stats().module_entries == 4


def test_public_cleanup_clean_and_report_rollback(tmp_path: Path) -> None:
    result = _result()
    fingerprint = hashlib.sha256(b"report").hexdigest()
    with CacheStore(tmp_path) as store:
        store.put_module(_key(), result)
        store.put_report(fingerprint, b"data")
        assert store.cleanup().total_bytes > 0
        store.clean()
        assert store.stats().module_entries == 0
        assert store.stats().report_entries == 0
        assert store.cleanup(force=True).total_bytes == 0


def test_cleanup_empty_and_context_close(tmp_path: Path) -> None:
    store = CacheStore(tmp_path)
    with store:
        assert store.cleanup().total_bytes == 0
        store.clean()
    with pytest.raises(RuntimeError):
        store.clean()


def test_report_invalid_and_stats_error_degrade(tmp_path: Path) -> None:
    with CacheStore(tmp_path) as store:
        assert store.get_report("bad") is None
        store._connection.close()  # type: ignore[union-attr]
        assert store.stats().total_bytes == 0


def test_codec_issue_variants_hooks_batch_and_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    metadata = module_cache.CacheMetadata(AdapterIdentity("python", "1"), "resolver")
    payload = module_cache.encode_module_result(_rich_result(), metadata)
    decoded = module_cache.decode_module_result(payload)
    assert decoded.value is not None and len(decoded.value.issues) == 4
    assert module_cache._enc_hook(object()) is msgspec.NODEFAULT
    assert module_cache._dec_hook(str, []) is msgspec.NODEFAULT
    batch = module_cache.decode_module_results(
        module_cache.encode_module_results((_result(), _rich_result()), metadata)
    )
    assert [item.value is not None for item in batch] == [True, True]
    monkeypatch.setattr(module_cache, "MAX_PAYLOAD_BYTES", 1)
    with pytest.raises(ValueError):
        module_cache.encode_module_result(_result(), metadata)


def test_codec_corruption_schema_trailing_and_raw_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    metadata = module_cache.CacheMetadata(AdapterIdentity("python", "1"), "resolver")
    payload = module_cache.encode_module_result(_result(), metadata)
    assert module_cache.decode_module_result(payload[:-1]).value is None
    assert module_cache.decode_module_result(payload + b"trailing").value is None
    raw = zlib.decompress(payload)
    envelope = module_cache._DECODER.decode(raw)
    bad = module_cache.CacheEnvelope(
        999, envelope.metadata, envelope.facts, envelope.issues, envelope.relations
    )
    bad_payload = zlib.compress(msgspec.msgpack.encode(bad, enc_hook=module_cache._enc_hook))
    assert module_cache.decode_module_result(bad_payload).value is None
    monkeypatch.setattr(module_cache, "MAX_UNCOMPRESSED_PAYLOAD_BYTES", 1)
    assert module_cache.decode_module_result(payload).value is None
