from __future__ import annotations

import json

from taut.domain.location import ConfigLocation, SourceRange
from taut.domain.reports import RunReport
from taut.domain.snapshot import ResolutionCoverage


def render_json(report: RunReport) -> str:
    payload = {
        "schema_version": report.run.report_schema_version,
        "engine_version": report.run.engine_version,
        "snapshot_id": report.run.snapshot_id.value,
        "decision_digest": report.run.decision_digest,
        "diagnostics": [
            {
                "rule_id": item.rule_id.value,
                "level": item.level.value,
                "message": item.message,
                "location": _source_location(item.primary_location),
                "related_locations": [
                    {"message": related.message, "location": _source_location(related.location)}
                    for related in item.related_locations
                ],
                "fingerprint": item.fingerprint.value,
                "disposition": item.disposition.value,
                "source": item.source.value,
                "help": item.help,
                "evidence": [
                    {"key": evidence.key, "value": evidence.value} for evidence in item.evidence
                ],
            }
            for item in report.diagnostics
        ],
        "engine_issues": [
            {
                "code": item.code,
                "kind": item.kind.value,
                "message": item.message,
                "location": _location(item.location),
                "cause": item.cause,
                "retryable": item.retryable,
            }
            for item in report.engine_issues
        ],
        "coverage": {
            "enabled_rules": report.coverage.enabled_rules,
            "total_targets": report.coverage.total_targets,
            "passed": report.coverage.passed,
            "failed": report.coverage.failed,
            "not_applicable": report.coverage.not_applicable,
            "indeterminate": report.coverage.indeterminate,
            "skipped": [
                {
                    "rule_id": item.rule_id.value,
                    "required_level": item.required_level.value,
                    "target": {
                        "kind": item.target.kind.value,
                        "module_id": item.target.module_id.value if item.target.module_id else None,
                        "symbol_id": item.target.symbol_id.value if item.target.symbol_id else None,
                        "fact_id": item.target.fact_id.value if item.target.fact_id else None,
                    },
                    "reason": {"code": item.reason.code, "message": item.reason.message},
                }
                for item in report.coverage.skipped
            ],
            "gaps": [
                {
                    "rule_id": item.rule_id.value,
                    "required_level": item.required_level.value,
                    "target": {
                        "kind": item.target.kind.value,
                        "module_id": item.target.module_id.value if item.target.module_id else None,
                        "symbol_id": item.target.symbol_id.value if item.target.symbol_id else None,
                        "fact_id": item.target.fact_id.value if item.target.fact_id else None,
                    },
                    "reason": {"code": item.reason.code, "message": item.reason.message},
                }
                for item in report.coverage.gaps
            ],
            "analysis": {
                "sources": {
                    "requested": report.analysis_coverage.requested_sources,
                    "complete": report.analysis_coverage.complete_modules,
                    "partial": report.analysis_coverage.partial_modules,
                    "failed": report.analysis_coverage.failed_modules,
                },
                "calls": _resolution_coverage(report.analysis_coverage.calls),
                "references": _resolution_coverage(report.analysis_coverage.references),
                "imports": {
                    "resolved": report.analysis_coverage.resolved_imports,
                    "unresolved": report.analysis_coverage.unresolved_imports,
                },
                "unavailable_capabilities": [
                    {"name": item.name, "reason": item.reason}
                    for item in report.analysis_coverage.unavailable_capabilities
                ],
            },
        },
        "ignores": {
            "used": report.ignore_audit.used,
            "unused": report.ignore_audit.unused,
        },
        "exit": {
            "code": report.exit_decision.code,
            "reasons": report.exit_decision.reasons,
        },
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)


def render_configuration_error_json(engine_version: str, message: str) -> str:
    payload = {
        "schema_version": 3,
        "engine_version": engine_version,
        "snapshot_id": None,
        "decision_digest": None,
        "diagnostics": [],
        "engine_issues": [
            {
                "code": "INVALID_CONFIGURATION",
                "kind": "invalid_configuration",
                "message": message,
                "location": None,
                "cause": None,
                "retryable": False,
            }
        ],
        "coverage": None,
        "ignores": None,
        "exit": {"code": 2, "reasons": ["설정 문제"]},
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)


def _source_location(location: SourceRange) -> dict[str, object]:
    return {
        "path": location.path.value,
        "start": {"line": location.start_line, "column": location.start_column},
        "end": {"line": location.end_line, "column": location.end_column},
    }


def _resolution_coverage(value: ResolutionCoverage) -> dict[str, int]:
    return {
        "resolved": value.resolved,
        "conditional": value.conditional,
        "ambiguous": value.ambiguous,
        "unresolved": value.unresolved,
        "dynamic": value.dynamic,
        "total": value.total,
    }


def _location(location: SourceRange | ConfigLocation | None) -> dict[str, object] | None:
    if location is None:
        return None
    if isinstance(location, SourceRange):
        return _source_location(location)
    return {"path": location.path.value, "line": location.line, "column": location.column}
