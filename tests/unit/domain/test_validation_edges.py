from __future__ import annotations

from pathlib import Path

import pytest
from tests.utils.builders import make_source

from taut.analysis.contracts import (
    AnalysisRequest,
    ContextManagerProvider,
    LanguageSettings,
    ProjectRoot,
    ResolverSettings,
    SourceInput,
)
from taut.configuration.manifest import Role, Zone
from taut.configuration.model import ProjectConfiguration
from taut.domain.diagnostics import Diagnostic, FindingDisposition
from taut.domain.evaluations import RuleLevel
from taut.domain.facts import (
    AnalysisStage,
    CompletenessState,
    ImportCycle,
    ModuleCompleteness,
    ModuleIdentity,
    ProjectIndex,
    SourceKind,
)
from taut.domain.findings import FindingSource
from taut.domain.frozen import FrozenMap
from taut.domain.ids import FindingFingerprint, ModuleId, RuleId, SnapshotId, SymbolId
from taut.domain.issues import EngineIssue, EngineIssueKind
from taut.domain.location import ConfigLocation, ConfigPath, ProjectPath, SourceRange
from taut.domain.provenance import Provenance
from taut.domain.reports import CoverageReport, ExitDecision, RunMetadata
from taut.domain.snapshot import AnalysisCoverage, AnalysisInputDigest
from taut.loading.config_loader import default_project_configuration


def test_project_root_and_source_input_validate_boundary_values() -> None:
    with pytest.raises(ValueError, match="absolute"):
        ProjectRoot(Path("relative"))
    source = make_source("app/a.py", "value = 1")
    with pytest.raises(ValueError, match="sha256"):
        SourceInput(
            source.path,
            source.module_id,
            source.kind,
            source.is_policy_target,
            source.is_package,
            source.content,
            "short",
        )


def test_analysis_request_rejects_unsorted_and_duplicate_inputs() -> None:
    first = make_source("app/a.py", "value = 1")
    second = make_source("app/b.py", "value = 2")
    with pytest.raises(ValueError, match="sorted"):
        AnalysisRequest(
            ProjectRoot(Path("/project")),
            (second, first),
            LanguageSettings(),
            ResolverSettings(),
            FrozenMap((("python", "1"),)),
        )
    with pytest.raises(ValueError, match="duplicate module"):
        AnalysisRequest(
            ProjectRoot(Path("/project")),
            (first, first),
            LanguageSettings(),
            ResolverSettings(),
            FrozenMap((("python", "1"),)),
        )


def test_resolver_settings_require_unique_sorted_context_manager_providers() -> None:
    first = ContextManagerProvider(SymbolId("app.first"), SymbolId("vendor.Item"))
    second = ContextManagerProvider(SymbolId("app.second"), SymbolId("vendor.Item"))

    with pytest.raises(ValueError, match="sorted"):
        ResolverSettings(context_manager_providers=(second, first))
    with pytest.raises(ValueError, match="unique"):
        ResolverSettings(context_manager_providers=(first, first))


def test_value_objects_reject_empty_or_invalid_content() -> None:
    location = SourceRange(ProjectPath("app/a.py"), 0, 0, 0, 0)
    with pytest.raises(ValueError, match="provider"):
        Provenance("", "1", "hash", location)
    with pytest.raises(ValueError, match="version"):
        Provenance("provider", "", "hash", location)
    with pytest.raises(ValueError, match="source hash"):
        Provenance("provider", "1", "", location)
    with pytest.raises(ValueError, match="line count"):
        ModuleIdentity(
            ModuleId("app.a"),
            ProjectPath("app/a.py"),
            SourceKind.FIRST_PARTY,
            True,
            False,
            -1,
        )
    with pytest.raises(ValueError, match="failed stage"):
        ModuleCompleteness(
            CompletenessState.FAILED,
            AnalysisStage.RESOLVED,
            frozenset(),
            FrozenMap(),
        )


def test_project_index_and_cycle_validate_graph_shape() -> None:
    module = ModuleId("app.a")
    with pytest.raises(ValueError, match="at least one"):
        ImportCycle(())
    with pytest.raises(ValueError, match="unique"):
        ImportCycle((module, module))
    with pytest.raises(ValueError, match="same modules"):
        ProjectIndex(
            FrozenMap(((module, ()),)),
            FrozenMap(),
            (),
            (),
        )


def test_issue_diagnostic_and_report_values_validate_messages() -> None:
    location = SourceRange(ProjectPath("app/a.py"), 0, 0, 0, 0)
    fingerprint = FindingFingerprint("0" * 64)
    with pytest.raises(ValueError, match="code"):
        EngineIssue("", EngineIssueKind.ANALYSIS_FAILURE, "message", None)
    with pytest.raises(ValueError, match="message"):
        Diagnostic(
            RuleId("TIME001"),
            RuleLevel.ENFORCED,
            "",
            location,
            (),
            (),
            None,
            fingerprint,
            FindingDisposition.ACTIVE,
            FindingSource.STATIC,
        )
    with pytest.raises(ValueError, match="non-zero"):
        ExitDecision(1, ())
    with pytest.raises(ValueError, match="0, 1, or 2"):
        ExitDecision(3, ("bad",))
    with pytest.raises(ValueError, match="positive"):
        RunMetadata("1", 0, SnapshotId("0" * 64), "digest")


def test_coverage_and_configuration_counts_validate() -> None:
    with pytest.raises(ValueError, match="requested source"):
        AnalysisCoverage(2, 1, 0, 0)
    with pytest.raises(ValueError, match="negative"):
        AnalysisCoverage(-1, 0, 0, -1)
    with pytest.raises(ValueError, match="target count"):
        CoverageReport(1, 2, 1, 0, 0, 0, ())
    with pytest.raises(ValueError, match="digest"):
        AnalysisInputDigest("")
    base = default_project_configuration()
    with pytest.raises(ValueError, match="include"):
        ProjectConfiguration(
            (),
            base.exclude,
            base.source_roots,
            base.manifest,
            base.catalog,
            base.policy,
        )
    assert str(Role("service")) == "service"
    assert str(Zone("prod")) == "prod"
    assert ConfigLocation(ProjectPath("policy.toml")).line is None
    assert ConfigPath("/tmp/audit-policy.toml").is_absolute
    with pytest.raises(ValueError, match="traverse"):
        ConfigPath("../audit-policy.toml")
