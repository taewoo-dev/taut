"""SQLite WAL cache storage; payload interpretation remains in strict codecs."""

from __future__ import annotations

import hashlib
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
    stdout: bytes
    stderr: bytes
    exit_code: int
    metadata: dict[str, str]


_REPORT_ENCODER = msgspec.msgpack.Encoder()
_REPORT_DECODER = msgspec.msgpack.Decoder(ReportEnvelope)


class CacheStore:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.path = directory / "cache.sqlite3"
        self._connection: sqlite3.Connection | None = None

    def __enter__(self) -> CacheStore:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=NORMAL")
            self._connection.execute("PRAGMA busy_timeout=5000")
            self._schema()
        except (sqlite3.DatabaseError, OSError):
            self._close_and_quarantine()
            self._connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            self._schema()
        return self

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
            (key.source_hash, key.adapter.name, key.adapter.version, key.resolver_identity)
        )

    def put_module(self, key: CacheKey, result: ModuleAnalysisResult) -> bool:
        payload = encode_module_result(result, CacheMetadata(key.adapter, key.resolver_identity))
        now = time.time()
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "INSERT OR REPLACE INTO module_entries VALUES (?,?,?,?,?,?,?,?,?)",
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
        try:
            row = (
                self._conn()
                .execute("SELECT payload FROM module_entries WHERE key=?", (self._key(key),))
                .fetchone()
            )
            if row is None:
                return None
            decoded = decode_module_result(bytes(row[0]))
            if decoded.value is None or decoded.metadata != CacheMetadata(
                key.adapter, key.resolver_identity
            ):
                self._conn().execute("DELETE FROM module_entries WHERE key=?", (self._key(key),))
                return None
            self._conn().execute(
                "UPDATE module_entries SET accessed=? WHERE key=?", (time.time(), self._key(key))
            )
            return decoded.value
        except (sqlite3.DatabaseError, OSError, ValueError, TypeError):
            return None

    def put_report(self, fingerprint: str, payload: bytes) -> bool:
        if not _HASH.fullmatch(fingerprint):
            raise ValueError("report fingerprint must be lowercase sha256")
        payload = b"RPT1" + hashlib.sha256(payload).digest() + payload
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
            if (
                len(value) < 36
                or value[:4] != b"RPT1"
                or hashlib.sha256(value[36:]).digest() != value[4:36]
            ):
                self._conn().execute("DELETE FROM report_entries WHERE key=?", (fingerprint,))
                return None
            self._conn().execute(
                "UPDATE report_entries SET accessed=? WHERE key=?", (time.time(), fingerprint)
            )
            return value[36:]
        except (sqlite3.DatabaseError, OSError):
            return None

    def get_report_envelope(self, fingerprint: str) -> ReportEnvelope | None:
        payload = self.get_report(fingerprint)
        if payload is None:
            return None
        try:
            envelope = _REPORT_DECODER.decode(payload)
            return envelope if envelope.schema == 1 else None
        except (msgspec.DecodeError, TypeError, ValueError):
            return None

    def stats(self) -> CacheStats:
        try:
            conn = self._conn()
            modules, reports, total = conn.execute(
                "SELECT (SELECT count(*) FROM module_entries), "
                "(SELECT count(*) FROM report_entries), "
                "(SELECT coalesce(sum(size),0) FROM module_entries) + "
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
            conn.execute("DELETE FROM report_entries")
            conn.execute("COMMIT")
        except (sqlite3.DatabaseError, OSError):
            with suppress(sqlite3.DatabaseError):
                self._conn().execute("ROLLBACK")

    def _cleanup(self, conn: sqlite3.Connection, *, force: bool = False) -> None:
        cutoff = time.time() - MAX_AGE_SECONDS
        conn.execute("DELETE FROM module_entries WHERE accessed<?", (cutoff,))
        conn.execute("DELETE FROM report_entries WHERE accessed<?", (cutoff,))
        while (
            int(conn.execute("SELECT coalesce(sum(size),0) FROM module_entries").fetchone()[0])
            + int(conn.execute("SELECT coalesce(sum(size),0) FROM report_entries").fetchone()[0])
            > MAX_TOTAL_BYTES
        ):
            candidate = conn.execute(
                "SELECT kind,key FROM ("
                "SELECT 'module' kind,key,accessed,created FROM module_entries UNION ALL "
                "SELECT 'report',key,accessed,created FROM report_entries) "
                "ORDER BY accessed,created,kind,key LIMIT 1"
            ).fetchone()
            if candidate is None:
                break
            table = "module_entries" if candidate[0] == "module" else "report_entries"
            conn.execute(f"DELETE FROM {table} WHERE key=?", (candidate[1],))

    def _close_and_quarantine(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None
        suffix = f".corrupt.{time.time_ns()}"
        for path in (self.path, Path(f"{self.path}-wal"), Path(f"{self.path}-shm")):
            if path.exists():
                os.replace(path, Path(f"{path}{suffix}"))
