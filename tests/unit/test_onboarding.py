from __future__ import annotations

import io
import tomllib
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from taut.check_service import CheckRequest
from taut.configuration.assurance import (
    BUILTIN_ASSURANCE_FEATURES,
    AssuranceAssertion,
    AssuranceConfiguration,
    FeatureExpectation,
    ScopeExclusion,
)
from taut.domain.assurance import AssuranceIssue, AssuranceReport
from taut.domain.frozen import FrozenMap
from taut.loading.errors import PolicyConfigError
from taut.onboarding import (
    build_init_proposal,
    configuration_schema_payload,
    ensure_init_target_is_new,
    read_init_answers,
    write_init_configuration,
)
from taut.onboarding_architecture import architecture_policy
from taut.onboarding_contributors import OnboardingFrameworkSpec, onboarding_framework_specs
from taut.onboarding_policy import answer_policy, missing_policy_decisions
from taut.onboarding_preflight import preflight_questions
from taut.project_observation import observe_path, python_files


def test_init_answers_and_safe_targets_cover_error_contracts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert read_init_answers(None) is None
    monkeypatch.setattr("sys.stdin", io.StringIO("[]"))
    with pytest.raises(PolicyConfigError, match="JSON object"):
        read_init_answers("-")

    invalid = tmp_path / "invalid.json"
    invalid.write_text("{")
    with pytest.raises(PolicyConfigError, match="cannot read"):
        read_init_answers(str(invalid))

    valid = tmp_path / "valid.json"
    valid.write_text('{"features": {}}')
    assert read_init_answers(str(valid)) == {"features": {}}

    (tmp_path / "app.py").write_text("value = 1\n")
    proposal = build_init_proposal(tmp_path, None)
    with pytest.raises(PolicyConfigError, match="unresolved questions"):
        write_init_configuration(tmp_path, Path("pyproject.toml"), proposal)

    with pytest.raises(PolicyConfigError, match="invalid init feature"):
        build_init_proposal(
            tmp_path,
            {
                "schema_version": 6,
                "project_digest": proposal.project_digest,
                "architecture": {"accept_safe_observed_edges": True, "risky_edges": []},
                "size": {"accept_observed": True},
                "features": {"unknown": "required"},
            },
        )
    with pytest.raises(PolicyConfigError, match="features must be an object"):
        build_init_proposal(
            tmp_path,
            {
                "schema_version": 6,
                "project_digest": proposal.project_digest,
                "architecture": {"accept_safe_observed_edges": True, "risky_edges": []},
                "size": {"accept_observed": True},
                "features": [],
            },
        )

    ready = build_init_proposal(
        tmp_path,
        {
            "schema_version": 6,
            "project_digest": proposal.project_digest,
            "architecture": {"accept_safe_observed_edges": True, "risky_edges": []},
            "size": {"accept_observed": True},
            "roles": {"app.py": "application"},
            "features": {feature: "absent" for feature in BUILTIN_ASSURANCE_FEATURES},
        },
    )
    target = Path("taut.toml")
    write_init_configuration(tmp_path, target, ready)
    assert (tmp_path / target).read_text().startswith("schema_version = 5")
    with pytest.raises(PolicyConfigError, match="configuration already exists"):
        write_init_configuration(tmp_path, target, ready)

    standalone = tmp_path / "taut.toml"
    standalone.write_text("schema_version = 5\n")
    with pytest.raises(PolicyConfigError, match="configuration already exists"):
        ensure_init_target_is_new(tmp_path, standalone)

    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[tool.taut\n")
    with pytest.raises(PolicyConfigError, match="cannot read pyproject"):
        ensure_init_target_is_new(tmp_path, pyproject)


def test_assurance_value_objects_reject_ambiguous_exceptions() -> None:
    with pytest.raises(ValueError, match="non-empty patterns"):
        ScopeExclusion((), "reason")
    with pytest.raises(ValueError, match="requires a reason"):
        ScopeExclusion(("generated/*.py",), "")
    with pytest.raises(ValueError, match="unknown assurance"):
        AssuranceAssertion("unknown", "path", "x.py", "not_applicable", "reason")
    with pytest.raises(ValueError, match="kind"):
        AssuranceAssertion("dto", "glob", "x.py", "not_applicable", "reason")
    with pytest.raises(ValueError, match="state"):
        AssuranceAssertion("dto", "path", "x.py", "ignored", "reason")
    with pytest.raises(ValueError, match="cannot be empty"):
        AssuranceAssertion("dto", "path", "", "not_applicable", "reason")
    with pytest.raises(ValueError, match="unknown assurance features"):
        AssuranceConfiguration(FrozenMap({"unknown": FeatureExpectation.ABSENT}))
    with pytest.raises(ValueError, match="cannot be negative"):
        AssuranceConfiguration(FrozenMap(), max_approvals=-1)
    with pytest.raises(ValueError, match="unique and sorted"):
        AssuranceConfiguration(
            FrozenMap(),
            exclusions=(
                ScopeExclusion(("z/*.py",), "z"),
                ScopeExclusion(("a/*.py",), "a"),
            ),
        )
    with pytest.raises(ValueError, match="values cannot be empty"):
        AssuranceIssue("", "message", "subject", "fix")
    assert AssuranceConfiguration.all_absent().features["api"] is FeatureExpectation.ABSENT
    assert AssuranceConfiguration.non_strict_default().features == FrozenMap()
    assert AssuranceReport().complete is True
    assert configuration_schema_payload()["schema_version"] == 5


def test_external_calls_do_not_require_an_invented_wrapper_during_init() -> None:
    expectations = {feature: "absent" for feature in BUILTIN_ASSURANCE_FEATURES}
    expectations["external_calls"] = "required"

    assert missing_policy_decisions(expectations, answer_policy({})) == ()


def test_getting_started_document_covers_the_machine_onboarding_contract() -> None:
    project_root = Path(__file__).parents[2]
    readme = (project_root / "README.md").read_text()
    guide = (project_root / "docs" / "getting-started.md").read_text()

    for document in (readme, guide):
        assert 'test "$?" -eq 2' in document
        assert "Python" in document and "digest" in document
        assert "accept_safe_observed_edges" in document
        assert "risky_edges" in document
        assert "accept_observed_source_scope" in document
        assert "source_roots" in document and "workspace" in document
        assert "does not" in document and "role" in document
        assert "taut audit" in document and "taut check" in document
    for feature in BUILTIN_ASSURANCE_FEATURES:
        assert f'"{feature}"' in guide
    assert "Prompt for an AI coding agent" in guide
    assert "SOURCE_UNACCOUNTED" in guide
    assert "FEATURE_POLICY_INACTIVE" in guide


def test_init_classifies_conventional_singular_and_plural_role_directories(
    tmp_path: Path,
) -> None:
    expected = {
        "router": ("router", "routers"),
        "dto": ("dto", "dtos"),
        "snapshot": ("snapshot", "snapshots"),
        "exception": ("exceptions", "errors"),
        "enum": ("enum", "enums"),
        "schema": ("schema", "schemas"),
        "model": ("model", "models"),
        "repository": ("repository", "repositories"),
        "validator": ("validator", "validators"),
        "aggregator": ("aggregator", "aggregators"),
        "adapter": ("adapter", "adapters", "client", "clients"),
        "service": ("service", "services"),
        "configuration": ("config", "configuration", "settings"),
    }
    for directories in expected.values():
        for directory in directories:
            source = tmp_path / "src" / "app" / directory / "orders.py"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("value = 1\n")

    proposal = build_init_proposal(tmp_path, None)
    roles = tomllib.loads(proposal.toml)["tool"]["taut"]["roles"]

    for role, directories in expected.items():
        includes = roles[role]["include"]
        assert all(f"src/app/{directory}/*.py" in includes for directory in directories)


def test_init_classifies_api_version_modules_and_ignores_snapshot_comments(
    tmp_path: Path,
) -> None:
    route = tmp_path / "src" / "app" / "api" / "v1" / "orders.py"
    route.parent.mkdir(parents=True)
    route.write_text("value = 1\n")
    conftest = tmp_path / "conftest.py"
    conftest.write_text("# Context - Snapshot\n")

    proposal = build_init_proposal(tmp_path, None)
    roles = tomllib.loads(proposal.toml)["tool"]["taut"]["roles"]

    assert roles["router"]["include"] == ["src/app/api/v1/orders.py"]
    assert roles["test"]["include"] == ["conftest.py"]
    assert "snapshot" not in proposal.detected_features


def test_init_proposes_only_providers_supported_by_import_evidence(tmp_path: Path) -> None:
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter\nfrom pydantic import BaseModel\n"
    )

    proposal = build_init_proposal(tmp_path, None)

    assert proposal.providers == ("taut.python-core", "taut.fastapi", "taut.pydantic")
    assert "taut.sqlalchemy" not in proposal.toml
    assert "taut.tortoise" not in proposal.toml


def test_init_exposes_conflicting_role_evidence_and_requires_exact_override(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src" / "app" / "services" / "order_model.py"
    source.parent.mkdir(parents=True)
    source.write_text("from tortoise.models import Model\nclass Order(Model): pass\n")
    initial = build_init_proposal(tmp_path, None)
    complete_answers: dict[str, object] = {
        "schema_version": 6,
        "project_digest": initial.project_digest,
        "architecture": {"accept_safe_observed_edges": True, "risky_edges": []},
        "size": {"accept_observed": True},
        "accept_observed_source_scope": True,
        "features": {feature: "absent" for feature in BUILTIN_ASSURANCE_FEATURES},
    }

    conflicted = build_init_proposal(tmp_path, complete_answers)

    assert conflicted.status == "needs_input"
    observation = conflicted.role_observations[0]
    assert observation.path == "src/app/services/order_model.py"
    assert observation.recommended == "service"
    assert observation.candidates == ("service", "model")
    assert observation.requires_review is True
    assert any(question.id == f"role.{observation.path}" for question in conflicted.questions)
    discovered = conflicted.json_payload()["discovered"]
    assert isinstance(discovered, dict)
    assert conflicted.json_payload()["schema_version"] == 6
    assert discovered["roles"] == [observation.json_payload()]

    complete_answers["roles"] = {observation.path: "model"}
    complete_answers["features"] = {
        feature: "required" if feature == "database" else "absent"
        for feature in BUILTIN_ASSURANCE_FEATURES
    }
    resolved = build_init_proposal(tmp_path, complete_answers)

    assert resolved.status == "ready"
    assert resolved.role_observations[0].recommended == "model"
    assert resolved.role_observations[0].confidence == "explicit"
    roles = tomllib.loads(resolved.toml)["tool"]["taut"]["roles"]
    assert roles["model"]["include"] == [observation.path]


def test_init_role_aliases_are_exact_reviewable_directory_decisions(tmp_path: Path) -> None:
    source = tmp_path / "src" / "app" / "usecases" / "orders.py"
    source.parent.mkdir(parents=True)
    source.write_text("value = 1\n")
    initial = build_init_proposal(tmp_path, None)
    answers: dict[str, object] = {
        "schema_version": 6,
        "project_digest": initial.project_digest,
        "architecture": {"accept_safe_observed_edges": True, "risky_edges": []},
        "size": {"accept_observed": True},
        "accept_observed_source_scope": True,
        "features": {feature: "absent" for feature in BUILTIN_ASSURANCE_FEATURES},
        "role_aliases": {"usecases": "service"},
    }

    proposal = build_init_proposal(tmp_path, answers)

    assert proposal.status == "ready"
    observation = proposal.role_observations[0]
    assert observation.recommended == "service"
    assert observation.confidence == "high"
    assert observation.evidence[0].kind == "custom_directory_alias"


def test_init_requires_one_explicit_response_mapper_when_project_convention_differs(
    tmp_path: Path,
) -> None:
    source = tmp_path / "app" / "schemas" / "user.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """from pydantic import BaseModel
class UserResponse(BaseModel):
    @classmethod
    def from_result(cls, value):
        return cls.model_validate(value)
"""
    )

    proposal = build_init_proposal(tmp_path, None)

    discovered = cast(dict[str, object], proposal.json_payload()["discovered"])
    assert discovered["response_mappers"] == ("from_result",)
    mapper_question = next(item for item in proposal.questions if item.id == "policy.schema_mapper")
    assert mapper_question.choices == ("from_result",)


def test_init_requires_reviewed_size_budget_and_renders_explicit_override(tmp_path: Path) -> None:
    source = tmp_path / "app" / "services" / "orders.py"
    source.parent.mkdir(parents=True)
    source.write_text("\n".join(f"value_{index} = {index}" for index in range(30)) + "\n")
    initial = build_init_proposal(tmp_path, None)

    assert any(item.id == "size.accept_observed" for item in initial.questions)
    answers: dict[str, object] = {
        "schema_version": 6,
        "project_digest": initial.project_digest,
        "architecture": {"accept_safe_observed_edges": True, "risky_edges": []},
        "accept_observed_source_scope": True,
        "size": {"default_max_lines": 600, "role_max_lines": {"service": 250}},
        "features": {feature: "absent" for feature in BUILTIN_ASSURANCE_FEATURES},
    }
    ready = build_init_proposal(tmp_path, answers)

    assert ready.status == "ready"
    config = tomllib.loads(ready.toml)["tool"]["taut"]
    assert config["max_lines"] == 600
    assert config["role_max_lines"] == {"service": 250}


def test_init_observes_uv_workspace_and_hatch_source_roots(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[tool.uv.workspace]\nmembers = ["packages/*"]\n')
    member = tmp_path / "packages" / "orders"
    package = member / "src" / "orders"
    package.mkdir(parents=True)
    (member / "pyproject.toml").write_text(
        '[build-system]\nbuild-backend = "hatchling.build"\n'
        '[tool.hatch.build.targets.wheel]\npackages = ["src/orders"]\n'
    )
    (package / "__init__.py").write_text("")
    (package / "service.py").write_text("value = 1\n")
    (tmp_path / "conftest.py").write_text("value = 2\n")

    initial = build_init_proposal(tmp_path, None)
    scope = initial.json_payload()["discovered"]
    assert isinstance(scope, dict)
    source_scope = cast(dict[str, object], scope["source_scope"])
    assert source_scope["recommended_source_roots"] == (
        ".",
        "packages/orders/src",
    )
    assert any(question.id == "source_scope.accept_observed" for question in initial.questions)

    answers: dict[str, object] = {
        "schema_version": 6,
        "project_digest": initial.project_digest,
        "architecture": {"accept_safe_observed_edges": True, "risky_edges": []},
        "size": {"accept_observed": True},
        "accept_observed_source_scope": True,
        "roles": {"packages/orders/src/orders/__init__.py": "application"},
        "features": {
            feature: "required" if feature == "tests" else "absent"
            for feature in BUILTIN_ASSURANCE_FEATURES
        },
    }
    ready = build_init_proposal(tmp_path, answers)

    assert ready.status == "ready"
    config = tomllib.loads(ready.toml)["tool"]["taut"]
    assert config["source_roots"] == [".", "packages/orders/src"]


def test_init_requires_explicit_source_roots_for_conflicting_workspace_metadata(
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[tool.uv.workspace]\nmembers = ["packages/missing"]\n'
    )
    (tmp_path / "app.py").write_text("value = 1\n")
    initial = build_init_proposal(tmp_path, None)
    base_answers: dict[str, object] = {
        "schema_version": 6,
        "project_digest": initial.project_digest,
        "architecture": {"accept_safe_observed_edges": True, "risky_edges": []},
        "size": {"accept_observed": True},
        "roles": {"app.py": "application"},
        "features": {feature: "absent" for feature in BUILTIN_ASSURANCE_FEATURES},
    }

    with pytest.raises(PolicyConfigError, match="has conflicts"):
        build_init_proposal(
            tmp_path,
            {**base_answers, "accept_observed_source_scope": True},
        )

    resolved = build_init_proposal(tmp_path, {**base_answers, "source_roots": ["."]})
    assert resolved.status == "ready"


def test_init_requires_review_for_source_root_init_without_module_identity(
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[tool.hatch.build.targets.wheel]\npackages = ["src/app"]\n'
    )
    source = tmp_path / "src"
    package = source / "app"
    package.mkdir(parents=True)
    (source / "__init__.py").write_text("")
    (package / "__init__.py").write_text("")

    initial = build_init_proposal(tmp_path, None)

    assert any("non-importable __init__.py" in item for item in initial.source_scope.conflicts)
    answers: dict[str, object] = {
        "schema_version": 6,
        "project_digest": initial.project_digest,
        "source_roots": ["src"],
        "architecture": {"accept_safe_observed_edges": True, "risky_edges": []},
        "size": {"accept_observed": True},
        "exclusions": [{"patterns": ["src/__init__.py"], "reason": "not an importable package"}],
        "roles": {"src/app/__init__.py": "application"},
        "features": {feature: "absent" for feature in BUILTIN_ASSURANCE_FEATURES},
    }
    resolved = build_init_proposal(tmp_path, answers)

    assert resolved.status == "ready"


def test_init_digest_includes_package_metadata(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nname = "example"\n')
    (tmp_path / "app.py").write_text("value = 1\n")
    initial = build_init_proposal(tmp_path, None)
    pyproject.write_text('[project]\nname = "renamed"\n')

    with pytest.raises(PolicyConfigError, match="stale"):
        build_init_proposal(
            tmp_path,
            {
                "schema_version": 6,
                "project_digest": initial.project_digest,
                "architecture": {"accept_safe_observed_edges": True, "risky_edges": []},
                "size": {"accept_observed": True},
                "features": {feature: "absent" for feature in BUILTIN_ASSURANCE_FEATURES},
            },
        )


def test_init_renders_reasoned_scope_and_exact_policy_answers(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("value = 1\n")
    spec = tmp_path / "spec" / "test_policy.py"
    spec.parent.mkdir()
    spec.write_text("def test_policy(): pass\n")
    generated = tmp_path / "generated" / "client.py"
    generated.parent.mkdir()
    generated.write_text("value = 2\n")
    initial = build_init_proposal(tmp_path, None)
    answers: dict[str, object] = {
        "schema_version": 6,
        "project_digest": initial.project_digest,
        "architecture": {"accept_safe_observed_edges": True, "risky_edges": []},
        "size": {"accept_observed": True},
        "roles": {"app.py": "application", "spec/test_policy.py": "test"},
        "zones": {"test": ["spec/**"]},
        "exclusions": [
            {
                "patterns": ["generated/**"],
                "reason": "generated from the checked-in service contract",
            }
        ],
        "policy": {
            "code_conventions": {
                "request_config_symbols": ["app.REQUEST_CONFIG"],
                "exception_base_symbols": ["app.DomainError"],
                "error_code_enum_symbols": ["app.ErrorCode"],
            },
            "transaction": {
                "owner_roles": ["application"],
                "session_providers": ["app.transaction"],
                "provider_item_types": {"app.transaction": "app.Session"},
            },
            "external": {
                "modules": ["vendor_sdk"],
                "logged_calls": ["vendor_sdk.Client.send"],
                "wrappers": ["app.logged_call"],
            },
            "enum": {"shared_modules": ["app"]},
        },
        "features": {
            feature: "required" if feature == "tests" else "absent"
            for feature in BUILTIN_ASSURANCE_FEATURES
        },
    }

    proposal = build_init_proposal(tmp_path, answers)
    config = tomllib.loads(proposal.toml)["tool"]["taut"]

    assert proposal.status == "ready"
    assert "exclude" not in config
    assert config["zones"]["test"] == ["spec/**"]
    assert config["exclusions"][0]["reason"].startswith("generated from")
    assert config["transaction"]["provider_item_types"] == {"app.transaction": "app.Session"}
    assert config["external"]["modules"] == ["vendor_sdk"]
    role_patterns = {path for matcher in config["roles"].values() for path in matcher["include"]}
    assert "generated/client.py" not in role_patterns


def test_init_requires_current_answers_schema_version(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("value = 1\n")
    initial = build_init_proposal(tmp_path, None)

    for version in (None, 3):
        answers: dict[str, object] = {"project_digest": initial.project_digest}
        if version is not None:
            answers["schema_version"] = version
        with pytest.raises(PolicyConfigError, match="schema_version must be 6"):
            build_init_proposal(tmp_path, answers)


@pytest.mark.parametrize(
    "metadata",
    [
        '[tool.setuptools.package-dir]\n"" = "src"\n',
        '[tool.poetry]\npackages = [{ include = "acme", from = "src" }]\n',
        '[tool.pdm.build]\npackage-dir = "src"\n',
    ],
)
def test_init_supports_standard_package_source_metadata(tmp_path: Path, metadata: str) -> None:
    (tmp_path / "pyproject.toml").write_text(metadata)
    package = tmp_path / "src" / "acme"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")

    proposal = build_init_proposal(tmp_path, None)

    assert proposal.source_roots == ("src",)
    assert proposal.source_scope.conflicts == ()
    assert any(item.confidence == "high" for item in proposal.source_scope.evidence)


@pytest.mark.parametrize(
    ("source_answer", "message"),
    [
        ({"source_roots": []}, "non-empty string array"),
        ({"source_roots": ["missing"]}, "does not exist"),
        ({"source_roots": ["src"]}, "do not cover every"),
        (
            {"accept_observed_source_scope": True, "source_roots": ["."]},
            "cannot combine",
        ),
    ],
)
def test_init_rejects_invalid_or_incomplete_source_scope_answers(
    tmp_path: Path, source_answer: dict[str, object], message: str
) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("value = 1\n")
    (tmp_path / "root_script.py").write_text("value = 2\n")
    initial = build_init_proposal(tmp_path, None)
    answers: dict[str, object] = {
        "schema_version": 6,
        "project_digest": initial.project_digest,
        "architecture": {"accept_safe_observed_edges": True, "risky_edges": []},
        "size": {"accept_observed": True},
        "features": {feature: "absent" for feature in BUILTIN_ASSURANCE_FEATURES},
        **source_answer,
    }

    with pytest.raises(PolicyConfigError, match=message):
        build_init_proposal(tmp_path, answers)


def test_init_prefers_structural_role_evidence_while_exposing_semantic_conflicts(
    tmp_path: Path,
) -> None:
    main = tmp_path / "src" / "app" / "main.py"
    main.parent.mkdir(parents=True)
    main.write_text("from fastapi import APIRouter\nrouter = APIRouter()\n")
    route = tmp_path / "src" / "app" / "routers" / "orders.py"
    route.parent.mkdir(parents=True)
    route.write_text("from pydantic import BaseModel\nclass Request(BaseModel): pass\n")

    proposal = build_init_proposal(tmp_path, None)
    observations = {item.path: item for item in proposal.role_observations}

    assert observations["src/app/main.py"].candidates == ("bootstrap", "router")
    assert observations["src/app/routers/orders.py"].candidates == ("router", "schema")
    assert all(item.requires_review for item in observations.values())


def test_init_allow_graph_uses_canonical_relative_import_resolution(tmp_path: Path) -> None:
    service = tmp_path / "src" / "app" / "services" / "orders.py"
    service.parent.mkdir(parents=True)
    service.write_text("def load(): return 1\n")
    router = tmp_path / "src" / "app" / "routers" / "orders.py"
    router.parent.mkdir(parents=True)
    router.write_text("from ..services import orders\n")
    initial = build_init_proposal(tmp_path, None)
    answers: dict[str, object] = {
        "schema_version": 6,
        "project_digest": initial.project_digest,
        "architecture": {"accept_safe_observed_edges": True, "risky_edges": []},
        "size": {"accept_observed": True},
        "accept_observed_source_scope": True,
        "features": {feature: "absent" for feature in BUILTIN_ASSURANCE_FEATURES},
    }

    proposal = build_init_proposal(tmp_path, answers)
    allow = tomllib.loads(proposal.toml)["tool"]["taut"]["allow"]

    assert "service" in allow["router"]


@pytest.mark.parametrize(
    ("update", "message"),
    [
        ({"unexpected": True}, "unknown init answer keys"),
        (
            {"architecture": {"accept_safe_observed_edges": "yes"}},
            "must be a boolean",
        ),
        ({"roles": {"missing.py": "service"}}, "does not match"),
        ({"role_aliases": {"bad/path": "service"}}, "invalid init role alias"),
        (
            {"role_aliases": {"services": "repository"}},
            "cannot redefine built-in directory",
        ),
    ],
)
def test_init_rejects_ambiguous_or_stale_role_answers(
    tmp_path: Path, update: dict[str, object], message: str
) -> None:
    (tmp_path / "app.py").write_text("value = 1\n")
    initial = build_init_proposal(tmp_path, None)
    answers: dict[str, object] = {
        "schema_version": 6,
        "project_digest": initial.project_digest,
        "architecture": {"accept_safe_observed_edges": True, "risky_edges": []},
        "size": {"accept_observed": True},
        "features": {feature: "absent" for feature in BUILTIN_ASSURANCE_FEATURES},
    }
    answers.update(update)

    with pytest.raises(PolicyConfigError, match=message):
        build_init_proposal(tmp_path, answers)


def test_project_observation_has_one_zone_and_one_inventory_contract(tmp_path: Path) -> None:
    included = tmp_path / "src" / "service.py"
    included.parent.mkdir()
    included.write_text("value = 1\n")
    ignored = tmp_path / ".tox" / "generated.py"
    ignored.parent.mkdir()
    ignored.write_text("value = 2\n")

    assert python_files(tmp_path) == ("src/service.py",)
    assert observe_path("tests/integration/migrations/revision.py").zone == "test"
    assert observe_path("scripts/tests/test_repair.py").zone == "test"
    assert observe_path("migrations/scripts/revision.py").zone == "migration"
    assert observe_path("scripts/repair.py").zone == "script"


def test_project_observation_includes_stubs_and_allows_explicit_ignored_paths(
    tmp_path: Path,
) -> None:
    stub = tmp_path / "src" / "contract.pyi"
    stub.parent.mkdir()
    stub.write_text("value: int\n")
    forced = tmp_path / "build" / "owned.py"
    forced.parent.mkdir()
    forced.write_text("value = 1\n")

    assert python_files(tmp_path) == ("src/contract.pyi",)
    assert python_files(tmp_path, ("build/owned.py",)) == (
        "build/owned.py",
        "src/contract.pyi",
    )


def test_init_groups_low_confidence_roles_and_accepts_reasoned_selector(tmp_path: Path) -> None:
    package = tmp_path / "app"
    package.mkdir()
    (package / "alpha.py").write_text("value = 1\n")
    (package / "beta.py").write_text("value = 2\n")
    initial = build_init_proposal(tmp_path, None)

    grouped = [item for item in initial.questions if item.id == "role_group.app"]
    assert len(grouped) == 1
    answers: dict[str, object] = {
        "schema_version": 6,
        "project_digest": initial.project_digest,
        "architecture": {"accept_safe_observed_edges": True, "risky_edges": []},
        "size": {"accept_observed": True},
        "features": {feature: "absent" for feature in BUILTIN_ASSURANCE_FEATURES},
        "role_selectors": [
            {
                "role": "application",
                "include": ["app/*.py"],
                "reason": "top-level application orchestration modules",
            }
        ],
    }

    resolved = build_init_proposal(tmp_path, answers)
    assert resolved.status == "ready"
    role = tomllib.loads(resolved.toml)["tool"]["taut"]["roles"]["application"]
    assert role["include"] == ["app/*.py"]
    assert 'reason: "top-level application orchestration modules"' in resolved.toml


def test_init_requires_individual_decisions_for_risky_architecture_edges(
    tmp_path: Path,
) -> None:
    service = tmp_path / "app" / "services" / "order.py"
    service.parent.mkdir(parents=True)
    service.write_text("from app.routers import order\n")
    router = tmp_path / "app" / "routers" / "order.py"
    router.parent.mkdir(parents=True)
    router.write_text("value = 1\n")
    initial = build_init_proposal(tmp_path, None)
    risky = next(edge for edge in initial.architecture_edges if edge[:2] == ("service", "router"))
    assert risky[2] is True
    answers: dict[str, object] = {
        "schema_version": 6,
        "project_digest": initial.project_digest,
        "architecture": {
            "accept_safe_observed_edges": True,
            "risky_edges": [
                {
                    "source": "service",
                    "target": "router",
                    "decision": "deny",
                    "reason": "services must not depend on delivery adapters",
                }
            ],
        },
        "size": {"accept_observed": True},
        "features": {feature: "absent" for feature in BUILTIN_ASSURANCE_FEATURES},
    }
    resolved = build_init_proposal(tmp_path, answers)
    assert "router" not in tomllib.loads(resolved.toml)["tool"]["taut"]["allow"]["service"]
    assert 'reason: "services must not depend on delivery adapters"' in resolved.toml


def test_external_provider_can_contribute_framework_onboarding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Contributor:
        id = "example.onboarding"
        version = "1"
        frameworks = (OnboardingFrameworkSpec("example.provider", ("exampleorm",)),)

    class Point:
        name = "example.onboarding"
        value = "example:Contributor"

        @staticmethod
        def load() -> type[Contributor]:
            return Contributor

    monkeypatch.setattr("taut.onboarding_contributors.entry_points", lambda: [Point()])
    (tmp_path / "models.py").write_text("import exampleorm\n")

    proposal = build_init_proposal(tmp_path, None)
    assert "example.provider" in proposal.providers


@pytest.mark.parametrize(
    ("answers", "message"),
    [
        ({"architecture": []}, "must be an object"),
        ({"architecture": {"unknown": True}}, "unknown init architecture"),
        ({"architecture": {"risky_edges": {}}}, "must be an array"),
        ({"architecture": {"risky_edges": ["edge"]}}, "must be an object"),
        (
            {"architecture": {"risky_edges": [{"source": "service"}]}},
            "requires source, target, decision, and reason",
        ),
        (
            {
                "architecture": {
                    "risky_edges": [
                        {
                            "source": "service",
                            "target": "router",
                            "decision": "sometimes",
                            "reason": "reviewed",
                        }
                    ]
                }
            },
            "must be allow or deny",
        ),
    ],
)
def test_init_architecture_answers_reject_ambiguous_contracts(
    answers: dict[str, object], message: str
) -> None:
    graph = {"service": {"service", "router"}, "router": {"router"}}
    with pytest.raises(PolicyConfigError, match=message):
        architecture_policy(answers, graph)


def test_onboarding_contributor_rejects_duplicate_framework_ownership(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Contributor:
        id = "example.conflict"
        version = "1"
        frameworks = (OnboardingFrameworkSpec("example.fastapi", ("fastapi",)),)

    class Point:
        name = "example.conflict"
        value = "example:Contributor"

        @staticmethod
        def load() -> type[Contributor]:
            return Contributor

    monkeypatch.setattr("taut.onboarding_contributors.entry_points", lambda: [Point()])
    with pytest.raises(PolicyConfigError, match="owned by both"):
        onboarding_framework_specs()
    with pytest.raises(ValueError, match="top-level"):
        OnboardingFrameworkSpec("example.provider", ("nested.module",))


def test_init_preflight_surfaces_engine_failure_as_a_blocking_question(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_check(request: CheckRequest) -> SimpleNamespace:
        return SimpleNamespace(
            report=None,
            issues=(SimpleNamespace(message=f"cannot analyze {request.project_root}"),),
        )

    monkeypatch.setattr(
        "taut.onboarding_preflight.run_check_request",
        fail_check,
    )
    questions = preflight_questions(tmp_path, "[tool.taut]\n")
    assert questions[0].id == "preflight.engine"
