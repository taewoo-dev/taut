"""Read-only configuration inspection and simplification commands."""

from __future__ import annotations

import json
from pathlib import Path

from taut.check_runtime import prepare_check_runtime
from taut.cli_workspace import configuration_payload
from taut.domain.location import ConfigPath
from taut.loading.config_simplification import simplify_configuration
from taut.loading.configuration_document import configuration_origins
from taut.loading.errors import PolicyConfigError
from taut.loading.source_discovery import discover_sources


def run_simplify(root: Path, config_path: ConfigPath | None) -> int:
    config = prepare_check_runtime(root, config_path).config
    print(simplify_configuration(root, config_path, config), end="")
    return 0


def run_explain(
    root: Path, config_path: ConfigPath | None, output_format: str, path: str | None = None
) -> int:
    config = prepare_check_runtime(root, config_path).config
    payload = configuration_payload(config)
    payload["origins"] = configuration_origins(root, config_path)
    payload["default_origin"] = "Taut built-in defaults (values not explicitly configured)"
    exit_code = 0
    if path is not None:
        try:
            relative = (root / path).resolve().relative_to(root).as_posix()
        except ValueError as error:
            raise PolicyConfigError("--path must be inside the selected project root") from error
        selected = config.manifest.role_for_path(relative)
        in_scope = any(
            source.path.value == relative for source in discover_sources(root, config).sources
        )
        payload["path"] = {
            "path": relative,
            "exists": (root / relative).is_file(),
            "in_scope": in_scope,
            "role": selected.role.value if selected else None,
            "priority": selected.priority if selected else None,
            "matching_selectors": [
                {
                    "role": matcher.role.value,
                    "priority": matcher.priority,
                    "patterns": matcher.patterns,
                }
                for matcher in config.manifest.roles
                if matcher.matches(relative)
            ],
            "allowed_imports": sorted(
                role.value for role in config.policy.allowed_imports.get(selected.role, frozenset())
            )
            if selected
            else [],
            "remediation": (
                "선언된 역할의 경로로 배치하고 책임을 맞추세요. "
                "새로운 아키텍처를 도입할 때만 규약을 수정하세요."
                if selected is None
                else "역할은 경로 규약으로 결정됩니다. 코드의 정책 준수 여부는 check로 검사하세요."
            ),
        }
        exit_code = 0 if selected is not None and in_scope else 2
    if output_format == "json":
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print(f"스키마: v{config.schema_version}")
        print(f"규칙 팩: {', '.join(config.packs)}")
        print(f"분석 provider: {', '.join(config.providers) or '(없음)'}")
        print(f"기본 영역: {config.manifest.default_zone.value}")
        print(f"최대 파일 길이: {config.policy.default_max_lines}")
        print(f"설정 digest: {config.digest()}")
        for key in (
            "path",
            "roles",
            "include",
            "exclude",
            "force_include",
            "zones",
            "effects",
            "assurance",
            "effective_policy",
            "origins",
            "default_origin",
        ):
            if key in payload:
                rendered = json.dumps(payload[key], ensure_ascii=False, sort_keys=True, indent=2)
                print(f"{key}: {rendered}")
    return exit_code
