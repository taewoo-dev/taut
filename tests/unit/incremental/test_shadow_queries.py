from __future__ import annotations

from dataclasses import replace

from tests.utils.builders import analyze, make_context, make_source

from taut.configuration.catalog import AccessPath, CatalogEntry, Effect
from taut.domain.frozen import FrozenMap
from taut.domain.ids import SymbolId
from taut.domain.query_dependencies import QueryDependencyGraph
from taut.incremental.shadow_queries import (
    build_function_summary_query_snapshot,
    compare_function_summary_invalidation,
)
from taut.policy.context import PolicyContext


def _effect_context(send: bool) -> PolicyContext:
    body = "    send()\n" if send else "    return None\n"
    return make_context(
        analyze(
            make_source("vendor.py", "def send(): pass\n"),
            make_source(
                "app/leaf.py",
                f"from vendor import send\ndef leaf():\n{body}",
            ),
            make_source(
                "app/caller.py",
                "from app.leaf import leaf\ndef caller():\n    leaf()\n",
            ),
        ),
        roles={"service": ("app/**", "vendor.py")},
        extra_catalog_entries=(
            CatalogEntry(
                SymbolId("vendor.send"),
                frozenset({Effect.EXTERNAL_CALL}),
                AccessPath.DIRECT,
            ),
        ),
    )


def test_shadow_invalidation_tracks_transitive_summary_changes() -> None:
    prior = build_function_summary_query_snapshot(_effect_context(False))
    current = build_function_summary_query_snapshot(_effect_context(True))

    result = compare_function_summary_invalidation(prior, current)

    assert result.sound
    assert {query.identity for query in result.observed_changed} == {
        "app.leaf.leaf",
        "app.caller.caller",
    }
    assert result.observed_changed <= result.proposed


def test_shadow_comparison_exposes_an_unsound_dependency_graph() -> None:
    prior = build_function_summary_query_snapshot(_effect_context(False))
    current = build_function_summary_query_snapshot(_effect_context(True))
    empty = QueryDependencyGraph(FrozenMap(), FrozenMap())

    result = compare_function_summary_invalidation(
        replace(prior, dependencies=empty),
        replace(current, dependencies=empty),
    )

    assert not result.sound
    assert result.missed == result.observed_changed


def test_semantically_irrelevant_body_edit_changes_no_summary_query() -> None:
    before = make_context(
        analyze(make_source("app/service.py", "def run() -> int:\n    return 1\n")),
        roles={"service": ("app/**",)},
    )
    after = make_context(
        analyze(make_source("app/service.py", "def run() -> int:\n    return 2\n")),
        roles={"service": ("app/**",)},
    )

    result = compare_function_summary_invalidation(
        build_function_summary_query_snapshot(before),
        build_function_summary_query_snapshot(after),
    )

    assert result.sound
    assert not result.proposed
    assert not result.observed_changed
