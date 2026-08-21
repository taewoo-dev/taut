"""Read-only all-module analysis/cache probe; prints metrics and writes nothing."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import taut.analysis.module_cache as cache
from taut.analysis.contracts import AdapterIdentity, ContextManagerProvider, ResolverSettings
from taut.analysis.module_cache import CacheMetadata, decode_module_result, encode_module_result
from taut.analysis.python.language_adapter import PythonAstAdapter
from taut.domain.ids import SymbolId
from taut.loading.config_loader import load_project_configuration
from taut.loading.source_discovery import discover_sources


def main() -> None:
    cache.MAX_NODES = 10_000_000
    root = Path(sys.argv[1]).resolve()
    config = load_project_configuration(root)
    sources = discover_sources(root, config).sources
    adapter = PythonAstAdapter()
    started = time.perf_counter()
    providers = tuple(
        sorted(
            {
                *(
                    ContextManagerProvider(symbol, SymbolId("sqlalchemy.ext.asyncio.AsyncSession"))
                    for symbol in config.policy.transaction_session_providers
                ),
                *(
                    ContextManagerProvider(symbol, symbol)
                    for symbol in config.policy.boundaries.http_timeout_calls
                ),
            }
        )
    )
    resolver = ResolverSettings(
        source_roots=config.source_roots, context_manager_providers=providers
    )
    results = adapter.analyze_modules(sources, resolver, workers=8)
    analysis_seconds = time.perf_counter() - started
    metadata = CacheMetadata(
        AdapterIdentity(adapter.identity.name, adapter.identity.version), "resolver-v1"
    )
    encoded_started = time.perf_counter()
    payloads = tuple(encode_module_result(result, metadata) for result in results)
    encode_seconds = time.perf_counter() - encoded_started
    decode_started = time.perf_counter()
    decoded = tuple(decode_module_result(payload) for payload in payloads)
    decode_seconds = time.perf_counter() - decode_started
    assert all(
        item.value == result and item.metadata == metadata
        for item, result in zip(decoded, results, strict=True)
    )
    total = sum(map(len, payloads))
    maximum = max(map(len, payloads), default=0)
    assert maximum < 64 * 1024 * 1024
    top = sorted(
        zip((source.path.value for source in sources), payloads, strict=True),
        key=lambda item: len(item[1]),
        reverse=True,
    )[:10]
    print(
        f"modules={len(results)} total_bytes={total} max_bytes={maximum} "
        f"analysis_seconds={analysis_seconds:.3f} encode_seconds={encode_seconds:.3f} "
        f"decode_seconds={decode_seconds:.3f}"
    )
    print("top=" + ",".join(f"{path}:{len(payload)}" for path, payload in top))


if __name__ == "__main__":
    main()
