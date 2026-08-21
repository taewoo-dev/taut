"""SQLite WAL cache storage; payload interpretation remains in strict codecs."""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from taut.analysis.contracts import AdapterIdentity, ModuleAnalysisResult
from taut.analysis.module_cache import CacheMetadata, decode_module_result, encode_module_result

SCHEMA_VERSION = 1
MAX_TOTAL_BYTES = 1 << 30
MAX_AGE_SECONDS = 30 * 24 * 60 * 60


class CacheMiss(Exception):
    """A cache lookup could not safely produce a value."""


@dataclass(frozen=True)
class CacheKey:
    source_hash: str
    adapter: AdapterIdentity
    resolver_identity: str


@dataclass(frozen=True)
class CacheStats:
    module_entries: int
    report_entries: int
    total_bytes: int


class CacheStore:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.path = directory / ".taut_cache" / "cache.sqlite3"
        self._connection: sqlite3.Connection | None = None

    def __enter__(self) -> CacheStore:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=NORMAL")
            self._connection.execute("PRAGMA busy_timeout=5000")
            self._schema()
        except (sqlite3.DatabaseError, OSError):
            self._close_and_quarantine()
            self._connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
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

    def _conn(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("CacheStore must be used as a context manager")
        return self._connection

    @staticmethod
    def _key(key: CacheKey) -> str:
        return "|".join(
            (key.source_hash, key.adapter.name, key.adapter.version, key.resolver_identity)
        )

    def put_module(self, key: CacheKey, result: ModuleAnalysisResult) -> None:
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
        except Exception:
            conn.execute("ROLLBACK")
            raise

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
                return None
            self._conn().execute(
                "UPDATE module_entries SET accessed=? WHERE key=?", (time.time(), self._key(key))
            )
            return decoded.value
        except (sqlite3.DatabaseError, ValueError, TypeError):
            return None

    def put_report(self, fingerprint: str, payload: bytes) -> None:
        now = time.time()
        self._conn().execute(
            "INSERT OR REPLACE INTO report_entries VALUES (?,?,?,?,?)",
            (fingerprint, payload, len(payload), now, now),
        )

    def get_report(self, fingerprint: str) -> bytes | None:
        row = (
            self._conn()
            .execute("SELECT payload FROM report_entries WHERE key=?", (fingerprint,))
            .fetchone()
        )
        return None if row is None else bytes(row[0])

    def stats(self) -> CacheStats:
        conn = self._conn()
        modules, reports, total = conn.execute(
            "SELECT (SELECT count(*) FROM module_entries), "
            "(SELECT count(*) FROM report_entries), "
            "(SELECT coalesce(sum(size),0) FROM module_entries) + "
            "(SELECT coalesce(sum(size),0) FROM report_entries)"
        ).fetchone()
        return CacheStats(int(modules), int(reports), int(total))

    def _cleanup(self, conn: sqlite3.Connection) -> None:
        cutoff = time.time() - MAX_AGE_SECONDS
        conn.execute("DELETE FROM module_entries WHERE accessed<?", (cutoff,))
        conn.execute("DELETE FROM report_entries WHERE accessed<?", (cutoff,))
        while self.stats().total_bytes > MAX_TOTAL_BYTES:
            conn.execute(
                "DELETE FROM module_entries WHERE key=(SELECT key FROM module_entries "
                "ORDER BY accessed LIMIT 1)"
            )

    def _close_and_quarantine(self) -> None:
        if self._connection is not None:
            self._connection.close()
        if self.path.exists():
            os.replace(self.path, self.path.with_suffix(".corrupt"))
