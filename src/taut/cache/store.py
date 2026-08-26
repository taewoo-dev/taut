"""SQLite WAL cache storage; payload interpretation remains in strict codecs."""

from __future__ import annotations

import os
import re
import sqlite3
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

import msgspec

from taut.analysis.contracts import AdapterIdentity, ModuleAnalysisResult
from taut.analysis.module_cache import CacheMetadata, decode_module_result, encode_module_result
from taut.cache.authenticated import MAGIC as AUTHENTICATED_MAGIC
from taut.cache.authenticated import (
    ModuleBundle,
    cache_signing_context,
    decode_authenticated_bundle,
    decode_authenticated_module,
    encode_authenticated_bundle,
    encode_authenticated_module,
)
from taut.cache.report_auth import decode_report, encode_report

SCHEMA_VERSION = 1
MAX_TOTAL_BYTES = 1 << 30
MAX_AGE_SECONDS = 30 * 24 * 60 * 60
_HASH = re.compile(r"^[0-9a-f]{64}$")


class CacheMiss(Exception):
    """A cache lookup could not safely produce a value."""


@dataclass(frozen=True)
class CacheKey:
    source_hash: str
    adapter: AdapterIdentity
    resolver_identity: str
    module_identity: str = ""

    def __post_init__(self) -> None:
        if not _HASH.fullmatch(self.source_hash):
            raise ValueError("source_hash must be lowercase sha256")
        if not all((self.adapter.name, self.adapter.version, self.resolver_identity)):
            raise ValueError("cache identity components must be nonempty")


@dataclass(frozen=True)
class CacheStats:
    module_entries: int
    report_entries: int
    total_bytes: int


class ReportEnvelope(msgspec.Struct, forbid_unknown_fields=True):
    """Versioned, byte-preserving report payload; only deterministic reports use it."""

    schema: int
    fingerprint: str
    stdout: bytes
    stderr: bytes
    exit_code: int
    metadata: dict[str, str]


_REPORT_ENCODER = msgspec.msgpack.Encoder()
_REPORT_DECODER = msgspec.msgpack.Decoder(ReportEnvelope)


class CacheStore:
    def __init__(self, directory: Path, *, signing_key: bytes | None = None) -> None:
        self.directory = directory
        self.path = directory / "cache.sqlite3"
        self._signing_key = signing_key
        self._connection: sqlite3.Connection | None = None

    @property
    def authenticated(self) -> bool:
        return self._signing_key is not None

    def __enter__(self) -> CacheStore:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for attempt in range(4):
            try:
                self._connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
                self._connection.execute("PRAGMA busy_timeout=30000")
                self._connection.execute("PRAGMA journal_mode=WAL")
                self._connection.execute("PRAGMA synchronous=NORMAL")
                self._schema()
                return self
            except (sqlite3.OperationalError, sqlite3.DatabaseError, OSError) as error:
                if self._is_lock_error(error) and attempt < 3:
                    self.__exit__(None, None, None)
                    time.sleep(0.02 * (attempt + 1))
                    continue
                self.__exit__(None, None, None)
                if isinstance(error, sqlite3.OperationalError) and self._is_lock_error(error):
                    raise
                self._close_and_quarantine()
                self._connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
                self._connection.execute("PRAGMA busy_timeout=30000")
                self._connection.execute("PRAGMA journal_mode=WAL")
                self._schema()
                return self
        raise RuntimeError("cache open retries exhausted")

    @staticmethod
    def _is_lock_error(error: BaseException) -> bool:
        code = getattr(error, "sqlite_errorcode", None)
        return code in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED) or any(
            token in str(error).lower() for token in ("locked", "busy")
        )

    def __exit__(self, *_: object) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def _schema(self) -> None:
        assert self._connection is not None
        self._connection.executescript(
            """CREATE TABLE IF NOT EXISTS cache_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS module_entries (
              key TEXT PRIMARY KEY, source_hash TEXT NOT NULL, adapter TEXT NOT NULL,
              adapter_version TEXT NOT NULL, resolver TEXT NOT NULL, payload BLOB NOT NULL,
              size INTEGER NOT NULL, created REAL NOT NULL, accessed REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS report_entries (
              key TEXT PRIMARY KEY, payload BLOB NOT NULL, size INTEGER NOT NULL,
              created REAL NOT NULL, accessed REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS module_bundles (
              key TEXT PRIMARY KEY, payload BLOB NOT NULL, module_count INTEGER NOT NULL,
              size INTEGER NOT NULL, created REAL NOT NULL, accessed REAL NOT NULL);
            INSERT OR IGNORE INTO cache_meta(key,value) VALUES ('schema','1');"""
        )
        value = self._connection.execute(
            "SELECT value FROM cache_meta WHERE key='schema'"
        ).fetchone()
        if value != (str(SCHEMA_VERSION),):
            raise sqlite3.DatabaseError("incompatible cache schema")

    def _conn(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("CacheStore must be used as a context manager")
        return self._connection

    @staticmethod
    def _key(key: CacheKey) -> str:
        return "|".join(
            (
                key.source_hash,
                key.adapter.name,
                key.adapter.version,
                key.resolver_identity,
                key.module_identity,
            )
        )

    def put_module(self, key: CacheKey, result: ModuleAnalysisResult) -> bool:
        return self.put_modules(((key, result),))

    def put_modules(self, entries: tuple[tuple[CacheKey, ModuleAnalysisResult], ...]) -> bool:
        if not entries:
            return True
        encoded = tuple(
            (
                key,
                self._encode_module(key, result),
            )
            for key, result in entries
        )
        now = time.time()
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.executemany(
                "INSERT OR REPLACE INTO module_entries VALUES (?,?,?,?,?,?,?,?,?)",
                tuple(
                    (
                        self._key(key),
                        key.source_hash,
                        key.adapter.name,
                        key.adapter.version,
                        key.resolver_identity,
                        payload,
                        len(payload),
                        now,
                        now,
                    )
                    for key, payload in encoded
                ),
            )
            self._cleanup(conn)
            conn.execute("COMMIT")
        except (sqlite3.DatabaseError, OSError):
            with suppress(sqlite3.DatabaseError):
                conn.execute("ROLLBACK")
            return False
        except Exception:
            with suppress(sqlite3.DatabaseError):
                conn.execute("ROLLBACK")
            raise
        return True

    def get_module(self, key: CacheKey) -> ModuleAnalysisResult | None:
        return self.get_modules((key,))[0]

    def get_modules(self, keys: tuple[CacheKey, ...]) -> tuple[ModuleAnalysisResult | None, ...]:
        if not keys:
            return ()
        try:
            conn = self._conn()
            storage_keys = tuple(self._key(key) for key in keys)
            rows: dict[str, bytes] = {}
            for chunk_start in range(0, len(storage_keys), 400):
                chunk = storage_keys[chunk_start : chunk_start + 400]
                placeholders = ",".join("?" for _ in chunk)
                rows.update(
                    (str(storage_key), bytes(payload))
                    for storage_key, payload in conn.execute(
                        f"SELECT key,payload FROM module_entries WHERE key IN ({placeholders})",
                        chunk,
                    )
                )
            values: list[ModuleAnalysisResult | None] = []
            valid: list[tuple[float, str]] = []
            invalid: list[tuple[str]] = []
            now = time.time()
            for key, storage_key in zip(keys, storage_keys, strict=True):
                payload = rows.get(storage_key)
                if payload is None:
                    values.append(None)
                    continue
                decoded = self._decode_module(key, payload)
                if decoded is None:
                    invalid.append((storage_key,))
                    values.append(None)
                    continue
                valid.append((now, storage_key))
                values.append(decoded)
            if invalid:
                conn.executemany("DELETE FROM module_entries WHERE key=?", invalid)
            if valid:
                conn.executemany("UPDATE module_entries SET accessed=? WHERE key=?", valid)
            return tuple(values)
        except (sqlite3.DatabaseError, OSError, ValueError, TypeError):
            return (None,) * len(keys)

    def _encode_module(self, key: CacheKey, result: ModuleAnalysisResult) -> bytes:
        if self._signing_key is not None:
            return encode_authenticated_module(
                result,
                context=self._signing_context(key),
                signing_key=self._signing_key,
            )
        return encode_module_result(result, CacheMetadata(key.adapter, key.resolver_identity))

    def _decode_module(self, key: CacheKey, payload: bytes) -> ModuleAnalysisResult | None:
        if payload.startswith(AUTHENTICATED_MAGIC):
            if self._signing_key is None:
                return None
            return decode_authenticated_module(
                payload,
                context=self._signing_context(key),
                signing_key=self._signing_key,
            )
        decoded = decode_module_result(payload)
        if decoded.metadata != CacheMetadata(key.adapter, key.resolver_identity):
            return None
        return decoded.value

    @staticmethod
    def _signing_context(key: CacheKey) -> bytes:
        return cache_signing_context(
            (
                key.source_hash,
                key.adapter.name,
                key.adapter.version,
                key.resolver_identity,
                key.module_identity,
            )
        )

    def put_module_bundle(self, bundle_key: str, bundle: ModuleBundle, *, context: bytes) -> bool:
        if not _HASH.fullmatch(bundle_key) or self._signing_key is None:
            return False
        try:
            payload = encode_authenticated_bundle(
                bundle, context=context, signing_key=self._signing_key
            )
        except (OSError, ValueError, TypeError):
            return False
        now = time.time()
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "INSERT OR REPLACE INTO module_bundles VALUES (?,?,?,?,?,?)",
                (bundle_key, payload, len(bundle.entries), len(payload), now, now),
            )
            self._cleanup(conn)
            conn.execute("COMMIT")
        except (sqlite3.DatabaseError, OSError):
            with suppress(sqlite3.DatabaseError):
                conn.execute("ROLLBACK")
            return False
        except Exception:
            with suppress(sqlite3.DatabaseError):
                conn.execute("ROLLBACK")
            raise
        return True

    def get_module_bundle(self, bundle_key: str, *, context: bytes) -> ModuleBundle | None:
        if not _HASH.fullmatch(bundle_key) or self._signing_key is None:
            return None
        try:
            row = (
                self._conn()
                .execute("SELECT payload FROM module_bundles WHERE key=?", (bundle_key,))
                .fetchone()
            )
            if row is None:
                return None
            bundle = decode_authenticated_bundle(
                bytes(row[0]), context=context, signing_key=self._signing_key
            )
            if bundle is None:
                self._conn().execute("DELETE FROM module_bundles WHERE key=?", (bundle_key,))
                return None
            self._conn().execute(
                "UPDATE module_bundles SET accessed=? WHERE key=?", (time.time(), bundle_key)
            )
            return bundle
        except (sqlite3.DatabaseError, OSError, ValueError, TypeError):
            return None

    def put_report(self, fingerprint: str, payload: bytes) -> bool:
        if not _HASH.fullmatch(fingerprint):
            raise ValueError("report fingerprint must be lowercase sha256")
        payload = encode_report(payload, fingerprint, self._signing_key)
        now = time.time()
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "INSERT OR REPLACE INTO report_entries VALUES (?,?,?,?,?)",
                (fingerprint, payload, len(payload), now, now),
            )
            self._cleanup(conn)
            conn.execute("COMMIT")
        except (sqlite3.DatabaseError, OSError):
            with suppress(sqlite3.DatabaseError):
                conn.execute("ROLLBACK")
            return False
        except Exception:
            with suppress(sqlite3.DatabaseError):
                conn.execute("ROLLBACK")
            raise
        return True

    def put_report_envelope(self, fingerprint: str, envelope: ReportEnvelope) -> bool:
        if envelope.fingerprint != fingerprint:
            return False
        return self.put_report(fingerprint, _REPORT_ENCODER.encode(envelope))

    def get_report(self, fingerprint: str) -> bytes | None:
        try:
            if not _HASH.fullmatch(fingerprint):
                return None
            row = (
                self._conn()
                .execute("SELECT payload FROM report_entries WHERE key=?", (fingerprint,))
                .fetchone()
            )
            if row is None:
                return None
            value = bytes(row[0])
            payload = decode_report(value, fingerprint, self._signing_key)
            if payload is None:
                self._conn().execute("DELETE FROM report_entries WHERE key=?", (fingerprint,))
                return None
            self._conn().execute(
                "UPDATE report_entries SET accessed=? WHERE key=?", (time.time(), fingerprint)
            )
            return payload
        except (sqlite3.DatabaseError, OSError):
            return None

    def get_report_envelope(self, fingerprint: str) -> ReportEnvelope | None:
        payload = self.get_report(fingerprint)
        if payload is None:
            return None
        try:
            envelope = _REPORT_DECODER.decode(payload)
            if envelope.schema != 1 or envelope.fingerprint != fingerprint:
                self._conn().execute("DELETE FROM report_entries WHERE key=?", (fingerprint,))
                return None
            return envelope
        except (msgspec.DecodeError, TypeError, ValueError):
            with suppress(sqlite3.DatabaseError):
                self._conn().execute("DELETE FROM report_entries WHERE key=?", (fingerprint,))
            return None

    def stats(self) -> CacheStats:
        try:
            conn = self._conn()
            modules, reports, total = conn.execute(
                "SELECT (SELECT count(*) FROM module_entries) + "
                "(SELECT coalesce(sum(module_count),0) FROM module_bundles), "
                "(SELECT count(*) FROM report_entries), "
                "(SELECT coalesce(sum(size),0) FROM module_entries) + "
                "(SELECT coalesce(sum(size),0) FROM module_bundles) + "
                "(SELECT coalesce(sum(size),0) FROM report_entries)"
            ).fetchone()
            return CacheStats(int(modules), int(reports), int(total))
        except (sqlite3.DatabaseError, OSError):
            return CacheStats(0, 0, 0)

    def cleanup(self, force: bool = False) -> CacheStats:
        try:
            conn = self._conn()
            conn.execute("BEGIN IMMEDIATE")
            self._cleanup(conn, force=force)
            conn.execute("COMMIT")
            if force:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                conn.execute("VACUUM")
            return self.stats()
        except (sqlite3.DatabaseError, OSError):
            with suppress(sqlite3.DatabaseError):
                self._conn().execute("ROLLBACK")
            return CacheStats(0, 0, 0)

    def clean(self) -> None:
        try:
            conn = self._conn()
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM module_entries")
            conn.execute("DELETE FROM module_bundles")
            conn.execute("DELETE FROM report_entries")
            conn.execute("COMMIT")
        except (sqlite3.DatabaseError, OSError):
            with suppress(sqlite3.DatabaseError):
                self._conn().execute("ROLLBACK")

    def _cleanup(self, conn: sqlite3.Connection, *, force: bool = False) -> None:
        cutoff = time.time() - MAX_AGE_SECONDS
        conn.execute("DELETE FROM module_entries WHERE accessed<?", (cutoff,))
        conn.execute("DELETE FROM module_bundles WHERE accessed<?", (cutoff,))
        conn.execute("DELETE FROM report_entries WHERE accessed<?", (cutoff,))
        while (
            int(conn.execute("SELECT coalesce(sum(size),0) FROM module_entries").fetchone()[0])
            + int(conn.execute("SELECT coalesce(sum(size),0) FROM module_bundles").fetchone()[0])
            + int(conn.execute("SELECT coalesce(sum(size),0) FROM report_entries").fetchone()[0])
            > MAX_TOTAL_BYTES
        ):
            candidate = conn.execute(
                "SELECT kind,key FROM ("
                "SELECT 'module' kind,key,accessed,created FROM module_entries UNION ALL "
                "SELECT 'bundle',key,accessed,created FROM module_bundles UNION ALL "
                "SELECT 'report',key,accessed,created FROM report_entries) "
                "ORDER BY accessed,created,kind,key LIMIT 1"
            ).fetchone()
            if candidate is None:
                break
            table = {
                "module": "module_entries",
                "bundle": "module_bundles",
                "report": "report_entries",
            }[candidate[0]]
            conn.execute(f"DELETE FROM {table} WHERE key=?", (candidate[1],))

    def _close_and_quarantine(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None
        suffix = f".corrupt.{time.time_ns()}"
        for path in (self.path, Path(f"{self.path}-wal"), Path(f"{self.path}-shm")):
            if path.exists():
                os.replace(path, Path(f"{path}{suffix}"))
