from __future__ import annotations

import dataclasses

# Test-only SQL corruption uses the store's private connection deliberately.
# pyright: reportPrivateUsage=false
import hashlib
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
from taut.cache.store import MAX_AGE_SECONDS, CacheKey, CacheStore
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
