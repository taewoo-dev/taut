"""Measure rule detection on labeled snippets without executing their source code."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Literal

import msgspec

from taut import __version__
from taut.check_service import CheckRequest, run_check_request
from taut.domain.ids import RuleId
from taut.policy.rules import builtin_rule_registry


class Case(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    id: str
    rule: str
    source: str
    violation: bool
    reason: str


class Corpus(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    schema_version: int
    kind: Literal["synthetic", "reviewed_snippets"]
    reviewer: str
    cases: tuple[Case, ...]


def evaluate(corpus: Corpus) -> dict[str, object]:
    if corpus.schema_version != 1 or not corpus.reviewer.strip() or not corpus.cases:
        raise ValueError("a v1 corpus requires a reviewer and at least one labeled case")
    if len({case.id for case in corpus.cases}) != len(corpus.cases):
        raise ValueError("case IDs must be unique")
    known = builtin_rule_registry().definitions
    rows: list[dict[str, object]] = []
    tp = fp = fn = tn = uncertain_positive = uncertain_negative = 0
    with tempfile.TemporaryDirectory(prefix="taut-detection-") as directory:
        root = Path(directory)
        (root / "app").mkdir()
        (root / "pyproject.toml").write_text(
            "[tool.taut]\nschema_version = 5\nstrict = false\n"
            '[tool.taut.roles]\nservice = ["app/*.py"]\n'
            '[tool.taut.allow]\nservice = ["service"]\n'
        )
        for case in corpus.cases:
            rule = RuleId(case.rule)
            if rule not in known or not all(v.strip() for v in (case.id, case.reason, case.source)):
                raise ValueError("every case requires a known rule, ID, source, and label reason")
            (root / "app/service.py").write_text(case.source)
            result = run_check_request(CheckRequest(root))
            if result.report is None or result.issues:
                raise ValueError(f"analysis failed for case {case.id}; no quality score emitted")
            found = any(finding.rule_id == rule for finding in result.findings)
            uncertain = any(
                issue.rule_id == rule
                for issue in (*result.report.coverage.skipped, *result.report.coverage.gaps)
            )
            observed = "violation" if found else "indeterminate" if uncertain else "no_finding"
            if case.violation:
                tp += int(found)
                fn += int(not found)
                uncertain_positive += int(uncertain and not found)
            else:
                fp += int(found)
                tn += int(not found and not uncertain)
                uncertain_negative += int(uncertain and not found)
            rows.append(
                {
                    "id": case.id,
                    "rule": case.rule,
                    "violation": case.violation,
                    "observed": observed,
                    "reason": case.reason,
                    "source_sha256": hashlib.sha256(case.source.encode()).hexdigest(),
                }
            )
    return {
        "schema_version": 1,
        "engine_version": __version__,
        "kind": corpus.kind,
        "reviewer": corpus.reviewer,
        "scope": "rule detection on snippets, not project assurance",
        "cases": rows,
        "metrics": {
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "true_negative": tn,
            "indeterminate_positive": uncertain_positive,
            "indeterminate_negative": uncertain_negative,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "positive_flag_rate": (tp + uncertain_positive) / (tp + fn) if tp + fn else None,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    arguments = parser.parse_args()
    path = Path(arguments.corpus)
    try:
        corpus = msgspec.json.decode(path.read_bytes(), type=Corpus)
        result = evaluate(corpus)
    except (OSError, ValueError, msgspec.DecodeError) as error:
        parser.exit(2, f"Invalid detection corpus: {error}\n")
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
