from __future__ import annotations

import io
from pathlib import Path

import pytest

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
                "project_digest": proposal.project_digest,
                "accept_observed_architecture": True,
                "features": {"unknown": "required"},
            },
        )
    with pytest.raises(PolicyConfigError, match="features must be an object"):
        build_init_proposal(
            tmp_path,
            {
                "project_digest": proposal.project_digest,
                "accept_observed_architecture": True,
                "features": [],
            },
        )

    ready = build_init_proposal(
        tmp_path,
        {
            "project_digest": proposal.project_digest,
            "accept_observed_architecture": True,
            "features": {feature: "absent" for feature in BUILTIN_ASSURANCE_FEATURES},
        },
    )
    target = Path("taut.toml")
    write_init_configuration(tmp_path, target, ready)
    assert (tmp_path / target).read_text().startswith("schema_version = 4")
    with pytest.raises(PolicyConfigError, match="configuration already exists"):
        write_init_configuration(tmp_path, target, ready)

    standalone = tmp_path / "taut.toml"
    standalone.write_text("schema_version = 4\n")
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
    assert configuration_schema_payload()["schema_version"] == 4


def test_getting_started_document_covers_the_machine_onboarding_contract() -> None:
    project_root = Path(__file__).parents[2]
    readme = (project_root / "README.md").read_text()
    guide = (project_root / "docs" / "getting-started.md").read_text()

    for document in (readme, guide):
        assert 'test "$?" -eq 2' in document
        assert "Python" in document and "digest" in document
        assert "accept_observed_architecture" in document
        assert "does not" in document and "role" in document
        assert "taut audit" in document and "taut check" in document
    for feature in BUILTIN_ASSURANCE_FEATURES:
        assert f'"{feature}"' in guide
    assert "Prompt for an AI coding agent" in guide
    assert "SOURCE_UNACCOUNTED" in guide
    assert "FEATURE_POLICY_INACTIVE" in guide
