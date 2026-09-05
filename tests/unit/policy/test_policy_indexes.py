from __future__ import annotations

from unittest.mock import patch

from tests.utils.builders import analyze, make_context, make_source

from taut.domain.ids import SymbolId
from taut.policy.context import PolicyContext


def _hierarchy_context() -> PolicyContext:
    snapshot = analyze(
        make_source("app/base.py", "class Root: pass\n"),
        make_source(
            "app/middle.py",
            "from app.base import Root\nclass Middle(Root): pass\n",
        ),
        make_source(
            "app/leaf.py",
            "from app.middle import Middle\nclass Leaf(Middle): pass\n",
        ),
    )
    return make_context(snapshot, roles={"service": ("app/**",)})


def test_hierarchy_queries_do_not_rescan_project_modules() -> None:
    context = _hierarchy_context()
    with patch.object(context.model, "module", wraps=context.model.module) as module:
        indexes = context.indexes
        build_calls = module.call_count

        for _ in range(100):
            assert context.symbol_in_or_inherits(
                SymbolId("app.leaf.Leaf"),
                frozenset({SymbolId("app.base.Root")}),
            )
            assert indexes.class_for(context.model, SymbolId("app.middle.Middle")) is not None

        assert module.call_count == build_calls


def test_candidate_sets_are_canonicalized_once_per_policy_revision() -> None:
    context = _hierarchy_context()
    candidates = frozenset(
        {
            SymbolId("app.base.Root"),
            SymbolId("external.Other"),
        }
    )
    with patch.object(
        context.model, "canonical_symbol", wraps=context.model.canonical_symbol
    ) as canonical_symbol:
        _ = context.indexes
        assert context.symbol_in(SymbolId("app.base.Root"), candidates)
        calls_after_first_lookup = canonical_symbol.call_count

        for _ in range(100):
            assert context.symbol_in(SymbolId("app.base.Root"), candidates)

        assert canonical_symbol.call_count - calls_after_first_lookup == 100


def test_hierarchy_index_terminates_deterministically_for_cycles() -> None:
    snapshot = analyze(
        make_source("app/a.py", "from app.b import B\nclass A(B): pass\n"),
        make_source("app/b.py", "from app.a import A\nclass B(A): pass\n"),
    )
    context = make_context(snapshot, roles={"service": ("app/**",)})

    assert context.indexes.class_ancestors == {
        SymbolId("app.a.A"): frozenset({SymbolId("app.a.A"), SymbolId("app.b.B")}),
        SymbolId("app.b.B"): frozenset({SymbolId("app.a.A"), SymbolId("app.b.B")}),
    }
    assert context.symbol_in_or_inherits(SymbolId("app.a.A"), frozenset({SymbolId("app.b.B")}))
