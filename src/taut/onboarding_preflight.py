"""Generated-configuration validation before init is allowed to write."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from taut.check_service import CheckRequest, run_check_request
from taut.domain.location import ConfigPath
from taut.onboarding_questions import InitQuestion


def preflight_questions(root: Path, toml: str) -> tuple[InitQuestion, ...]:
    content = toml.replace("[tool.taut]\n", "[tool.taut]\ncache = { enabled = false }\n", 1)
    descriptor, name = tempfile.mkstemp(prefix="taut-init-preflight.", suffix=".toml")
    try:
        with os.fdopen(descriptor, "w") as temporary:
            temporary.write(content)
        result = run_check_request(CheckRequest(root, ConfigPath(name), output_format="json"))
    finally:
        if os.path.exists(name):
            os.unlink(name)
    if result.report is None:
        evidence = tuple(issue.message for issue in result.issues) or (
            "generated configuration could not be analyzed",
        )
        return (
            InitQuestion(
                "preflight.engine",
                "생성 설정을 검증하지 못했습니다. source, selector, provider 설정을 수정하세요.",
                ("fix_configuration",),
                "fix_configuration",
                evidence,
            ),
        )
    return tuple(
        InitQuestion(
            f"preflight.assurance.{issue.code}.{issue.subject}",
            issue.message,
            ("fix_policy_or_code",),
            "fix_policy_or_code",
            (issue.subject, issue.remediation),
        )
        for issue in result.report.assurance.issues
    )
