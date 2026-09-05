from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import pytest
from tests.utils.builders import make_source

from taut.analysis.contracts import ModuleAnalysisResult, ResolverSettings, SourceInput
from taut.analysis.python.language_adapter import PythonAstAdapter


def test_small_pending_batch_stays_in_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class UnexpectedExecutor:
        def __init__(self, **_: object) -> None:
            raise AssertionError("small batches must not create a process pool")

    monkeypatch.setattr(
        "taut.analysis.python.language_adapter.ProcessPoolExecutor", UnexpectedExecutor
    )
    sources = (
        make_source("app/first.py", "first = 1"),
        make_source("app/second.py", "second = 2"),
    )

    results = PythonAstAdapter().analyze_modules(sources, ResolverSettings(), workers=4)

    assert tuple(result.facts.module.id.value for result in results) == (
        "app.first",
        "app.second",
    )


def test_parallel_batch_caps_workers_and_preserves_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, int] = {}

    class InlineExecutor:
        def __init__(self, *, max_workers: int) -> None:
            observed["workers"] = max_workers

        def __enter__(self) -> InlineExecutor:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def map(
            self,
            function: Any,
            sources: Iterable[SourceInput],
            resolvers: Iterable[ResolverSettings],
            *,
            chunksize: int,
        ) -> Iterable[ModuleAnalysisResult]:
            observed["chunksize"] = chunksize
            return map(function, sources, resolvers)

    monkeypatch.setattr("taut.analysis.python.language_adapter.ProcessPoolExecutor", InlineExecutor)
    sources = tuple(
        make_source(f"app/module_{index:03}.py", f"value = {index}") for index in range(100)
    )

    results = PythonAstAdapter().analyze_modules(sources, ResolverSettings(), workers=200)

    assert observed == {"workers": 100, "chunksize": 1}
    assert tuple(result.facts.module.id for result in results) == tuple(
        source.module_id for source in sources
    )
