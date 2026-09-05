from __future__ import annotations

import gc
import random
import weakref
from dataclasses import replace
from pathlib import Path

import pytest
from tests.utils.builders import make_context, make_source
from tests.utils.config import assurance_toml

from taut.analysis.contracts import AnalysisRequest, LanguageSettings, ProjectRoot, ResolverSettings
from taut.analysis.framework.fastapi import FastAPIProvider
from taut.analysis.framework.sqlalchemy import SQLAlchemyProvider
from taut.analysis.provider_reuse import local_provider_result
from taut.analysis.providers import (
    IncrementalFactProviderV1,
    apply_fact_providers,
    apply_fact_providers_incremental,
)
from taut.analysis.python.language_adapter import PythonAstAdapter
from taut.check_service import CheckRequest, ResidentCheckSession, run_check_request
from taut.domain.frozen import FrozenMap
from taut.domain.ids import ModuleId
from taut.domain.relations import ProjectRelations
from taut.domain.snapshot import AnalysisSnapshot
from taut.incremental.analyzer import IncrementalProjectAnalyzer
from taut.policy.effect_reuse import equivalent_effect_modules


def _request_many(values: dict[str, str]) -> AnalysisRequest:
    adapter = PythonAstAdapter()
    return AnalysisRequest(
        ProjectRoot(Path.cwd()),
        tuple(make_source(path, text) for path, text in sorted(values.items())),
        LanguageSettings(),
        ResolverSettings(),
        FrozenMap(((adapter.identity.name, adapter.identity.version),)),
    )


def _project(root: Path, files: dict[str, str]) -> CheckRequest:
    (root / "app").mkdir()
    for name, text in files.items():
        (root / "app" / name).write_text(text)
    (root / "pyproject.toml").write_text(
        "[tool.taut]\nschema_version=5\n"
        'providers=["taut.python-core", "taut.fastapi", "taut.sqlalchemy"]\n'
        'source_roots=["."]\n[tool.taut.roles]\nservice=["app/*.py"]\n'
        '[tool.taut.allow]\nservice=["service"]\n' + assurance_toml(pyproject=True)
    )
    return CheckRequest(root)


@pytest.mark.parametrize("provider", [FastAPIProvider(), SQLAlchemyProvider()])
def test_provider_export_certificate_matches_broad_and_fresh(
    provider: IncrementalFactProviderV1,
) -> None:
    values = {
        "app/config.py": "value = 1\n",
        "app/api.py": "from app.config import value\nfrom fastapi import APIRouter\n"
        'router = APIRouter()\n@router.get("/items")\ndef endpoint(): return value\n',
        "app/model.py": "from app.config import value\nfrom sqlalchemy.orm import DeclarativeBase\n"
        "class Base(DeclarativeBase): pass\nclass Model(Base): pass\n",
    }
    analyzer = IncrementalProjectAnalyzer(PythonAstAdapter())
    previous = apply_fact_providers(analyzer.analyze(_request_many(values)), (provider,))
    for source in ("value = 2\n", "value = 2\n# comment\n"):
        values["app/config.py"] = source
        current = analyzer.analyze(_request_many(values))
        impacted = analyzer.last_impact.impacted
        local = local_provider_result(provider, current, previous, previous.capabilities, impacted)
        assert local is not None
        assert local == provider.analyze_incremental(current, previous.capabilities, impacted)
        assert local == provider.analyze(current)
        previous = apply_fact_providers_incremental(
            current, (provider,), previous, impacted, reuse_selector=local_provider_result
        )


def test_provider_subclass_does_not_receive_builtin_optimization() -> None:
    class Custom(FastAPIProvider):
        pass

    analyzer = IncrementalProjectAnalyzer(PythonAstAdapter())
    snapshot = analyzer.analyze(_request_many({"app/a.py": "value = 1"}))
    provider = Custom()
    prior = apply_fact_providers(snapshot, (provider,))
    assert local_provider_result(provider, snapshot, prior, prior.capabilities, frozenset()) is None


def test_effect_certificate_rejects_changed_callback_behavior() -> None:
    values = {
        "app/helper.py": "def helper(): return 1\n",
        "app/service.py": "from app.helper import helper\nasync def work(): helper()\n",
    }
    analyzer = IncrementalProjectAnalyzer(PythonAstAdapter())
    before = make_context(analyzer.analyze(_request_many(values)), roles={"service": ("app/*.py",)})
    values["app/helper.py"] = "def helper(): return 2\n"
    after = make_context(analyzer.analyze(_request_many(values)), roles={"service": ("app/*.py",)})
    candidates = frozenset({ModuleId("app.service")})
    assert equivalent_effect_modules(after, before, candidates) == candidates
    values["app/helper.py"] = "import time\ndef helper(): time.sleep(1)\n"
    blocking = make_context(
        analyzer.analyze(_request_many(values)), roles={"service": ("app/*.py",)}
    )
    assert not equivalent_effect_modules(blocking, after, candidates)


def test_composing_relations_rejects_duplicate_bindings() -> None:
    snapshot = IncrementalProjectAnalyzer(PythonAstAdapter()).analyze(
        _request_many({"app/a.py": "value = 1\n"})
    )
    with pytest.raises(ValueError, match="binding ids must be unique"):
        ProjectRelations.from_validated_parts((snapshot.relations, snapshot.relations), ())


@pytest.mark.parametrize("seed", [20260905, 41, 997])
def test_hundred_mixed_edits_match_fresh_and_release_modules(tmp_path: Path, seed: int) -> None:
    request = replace(
        _project(
            tmp_path,
            {
                "helper.py": "def helper(): return 1\n",
                "service.py": "from app.helper import helper\nasync def work(): helper()\n",
            },
        ),
        output_format="json",
    )
    randomizer = random.Random(seed)
    helper = tmp_path / "app/helper.py"
    extra = tmp_path / "app/extra.py"
    with ResidentCheckSession(tmp_path) as session:
        session.check(request)
        for index in range(100):
            old = session._prior_provider_snapshot  # pyright: ignore[reportPrivateUsage]
            assert isinstance(old, AnalysisSnapshot)
            old_ref = weakref.ref(old)
            del old
            choice = randomizer.randrange(6)
            if choice == 0:
                helper.write_text(f"def helper(): return {index}\n")
            elif choice == 1:
                helper.write_text("import time\ndef helper(): time.sleep(1)\n")
            elif choice == 2:
                helper.write_text("def broken(:\n")
            elif choice == 3:
                extra.write_text(f"value = {index}\n")
            elif choice == 4:
                extra.unlink(missing_ok=True)
            else:
                helper.write_text(f"# moved {index}\ndef helper(): return 1\n")
            resident = session.check(request)
            fresh = run_check_request(request)
            assert (resident.stdout, resident.stderr, resident.exit_code) == (
                fresh.stdout,
                fresh.stderr,
                fresh.exit_code,
            )
            gc.collect()
            if session._prior_provider_snapshot is not old_ref():  # pyright: ignore[reportPrivateUsage]
                assert old_ref() is None
        session.reset()
        assert not session._evidence_cache.entries  # pyright: ignore[reportPrivateUsage]
