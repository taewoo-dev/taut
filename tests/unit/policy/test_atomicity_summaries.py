from __future__ import annotations

from dataclasses import replace

from tests.utils.builders import analyze, make_context, make_source

from taut.domain.ids import ModuleId, SymbolId
from taut.policy.context import PolicyContext


def _context(helper_body: str) -> PolicyContext:
    return make_context(
        analyze(
            make_source(
                "app/models.py",
                "from tortoise.models import Model\nclass User(Model): pass\n",
            ),
            make_source(
                "app/helper.py",
                "from app.models import User\nasync def helper():\n" + helper_body,
            ),
            make_source(
                "app/service.py",
                "from app.helper import helper\nasync def run():\n"
                "    await helper()\n    await helper()\n",
            ),
            make_source("app/unrelated.py", "def stable():\n    return None\n"),
        ),
        roles={"service": ("app/**",)},
    )


def test_incremental_atomicity_summary_matches_fresh_and_reuses_unrelated_functions() -> None:
    old = _context("    await User.create(name='old')\n")
    prior = old.atomicity_summary_state
    fresh = _context("    return None\n")
    incremental = replace(
        fresh,
        prior_atomicity_summary_state=prior,
        atomicity_summary_invalidated_modules=frozenset(
            {ModuleId("app.helper"), ModuleId("app.service")}
        ),
    )

    state = incremental.atomicity_summary_state

    assert state.summaries == fresh.atomicity_summary_state.summaries
    assert state.summaries[SymbolId("app.helper.helper")].upper == 0
    assert state.summaries[SymbolId("app.service.run")].upper == 0
    assert (
        state.functions[SymbolId("app.unrelated.stable")]
        is prior.functions[SymbolId("app.unrelated.stable")]
    )
    assert state.reused_functions == 1


def test_recursive_atomicity_summary_reaches_a_bounded_fixed_point() -> None:
    context = make_context(
        analyze(
            make_source(
                "app/models.py",
                "from tortoise.models import Model\nclass User(Model): pass\n",
            ),
            make_source(
                "app/service.py",
                "from app.models import User\n"
                "async def first():\n    await second()\n"
                "async def second():\n    await first()\n    await User.create()\n",
            ),
        ),
        roles={"service": ("app/**",)},
    )

    state = context.atomicity_summary_state

    assert state.summaries[SymbolId("app.service.first")].lower == 2
    assert state.summaries[SymbolId("app.service.second")].lower == 2
    assert state.processed_functions < 20


def test_atomic_boundary_cuts_transitive_write_propagation() -> None:
    context = make_context(
        analyze(
            make_source(
                "app/models.py",
                "from tortoise.models import Model\nclass User(Model): pass\n",
            ),
            make_source(
                "app/service.py",
                "from tortoise.transactions import atomic\nfrom app.models import User\n"
                "@atomic()\nasync def helper():\n    await User.create()\n"
                "async def run():\n    await helper()\n    await helper()\n",
            ),
        ),
        roles={"service": ("app/**",)},
    )

    state = context.atomicity_summary_state

    assert state.summaries[SymbolId("app.service.helper")].upper == 0
    assert state.summaries[SymbolId("app.service.run")].upper == 0
