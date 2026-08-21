"""Read-only all-module analysis/cache probe; prints metrics and writes nothing."""

from __future__ import annotations

import sys
import time
from pathlib import Path

from taut.analysis.contracts import AdapterIdentity, ResolverSettings
from taut.analysis.module_cache import CacheMetadata, decode_module_result, encode_module_result
from taut.analysis.python.language_adapter import PythonAstAdapter
from taut.loading.config_loader import load_project_configuration
from taut.loading.source_discovery import discover_sources


def main() -> None:
    root = Path(sys.argv[1]).resolve()
    config = load_project_configuration(root)
    sources = discover_sources(root, config).sources
    adapter = PythonAstAdapter()
    started = time.perf_counter()
    results = adapter.analyze_modules(
        sources, ResolverSettings(source_roots=config.source_roots), workers=8
    )
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
    assert maximum < 8 * 1024 * 1024
    print(
        f"modules={len(results)} total_bytes={total} max_bytes={maximum} "
        f"analysis_seconds={analysis_seconds:.3f} encode_seconds={encode_seconds:.3f} "
        f"decode_seconds={decode_seconds:.3f}"
    )


if __name__ == "__main__":
    main()
