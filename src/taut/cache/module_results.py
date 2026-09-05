"""Persistent per-module results and authenticated module bundles."""

from __future__ import annotations

import hashlib
from pathlib import Path

from taut.analysis.contracts import AdapterIdentity, ModuleAnalysisResult, SourceInput
from taut.cache.authenticated import ModuleBundle, cache_signing_context
from taut.cache.store import CacheKey, CacheStore


class DiskModuleCache:
    def __init__(
        self,
        store: CacheStore,
        adapter: AdapterIdentity,
        resolver_identity: str,
        project_root: Path,
    ) -> None:
        self._store = store
        self._adapter = adapter
        self._resolver_identity = resolver_identity
        self._bundle_context = cache_signing_context(
            (
                "module-bundle:1",
                str(project_root.resolve()),
                adapter.name,
                adapter.version,
                resolver_identity,
            )
        )
        self._bundle_key = hashlib.sha256(self._bundle_context).hexdigest()
        self._sources: tuple[SourceInput, ...] = ()
        self._cached: tuple[ModuleAnalysisResult | None, ...] = ()
        self._bundle_present = False

    def get_many(self, sources: tuple[SourceInput, ...]) -> tuple[ModuleAnalysisResult | None, ...]:
        self._sources = sources
        if not self._store.authenticated:
            self._cached = self._store.get_modules(tuple(self._key(source) for source in sources))
            return self._cached
        bundle = self._store.get_module_bundle(self._bundle_key, context=self._bundle_context)
        self._bundle_present = bundle is not None
        if bundle is None:
            individual = self._store.get_modules(tuple(self._key(source) for source in sources))
            if any(result is not None for result in individual):
                self._cached = individual
                return self._cached
        indexed: dict[str, tuple[str, ModuleAnalysisResult]] = {}
        if bundle is not None:
            for module_identity, source_hash, result in bundle.entries:
                if module_identity in indexed:
                    indexed.clear()
                    self._bundle_present = False
                    break
                indexed[module_identity] = (source_hash, result)
        values: list[ModuleAnalysisResult | None] = []
        for source in sources:
            entry = indexed.get(source.module_id.value)
            if (
                entry is None
                or entry[0] != source.content_hash
                or entry[1].facts.module.id != source.module_id
            ):
                values.append(None)
            else:
                values.append(entry[1])
        self._cached = tuple(values)
        return self._cached

    def put_many(self, entries: tuple[tuple[SourceInput, ModuleAnalysisResult], ...]) -> None:
        if not self._store.authenticated:
            self._store.put_modules(
                tuple((self._key(source), result) for source, result in entries)
            )
            return
        fresh = {source.module_id: result for source, result in entries}
        refresh_threshold = max(32, len(self._sources) // 4)
        if self._bundle_present and len(entries) < refresh_threshold:
            return
        combined: list[tuple[str, str, ModuleAnalysisResult]] = []
        for source, cached in zip(self._sources, self._cached, strict=True):
            result = fresh.get(source.module_id, cached)
            if result is None or result.facts.module.id != source.module_id:
                return
            combined.append((source.module_id.value, source.content_hash, result))
        stored = self._store.put_module_bundle(
            self._bundle_key,
            ModuleBundle(tuple(combined)),
            context=self._bundle_context,
        )
        if not stored:
            self._store.put_modules(
                tuple((self._key(source), result) for source, result in entries)
            )

    def _key(self, source: SourceInput) -> CacheKey:
        return CacheKey(
            source.content_hash,
            self._adapter,
            self._resolver_identity,
            source.module_id.value,
        )
