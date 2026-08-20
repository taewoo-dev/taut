from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from taut import __version__
from taut.analysis.contracts import (
    AnalysisRequest,
    ContextManagerProvider,
    LanguageSettings,
    ProjectRoot,
    ResolverSettings,
)
from taut.analysis.project_analyzer import ProjectAnalyzer
from taut.analysis.providers import apply_fact_providers
from taut.analysis.python.language_adapter import PythonAstAdapter
from taut.analysis.semantic_model import SnapshotSemanticModel
from taut.configuration.catalog import EffectResolver
from taut.configuration.validation import validate_classification_for_policy
from taut.domain.frozen import FrozenMap
from taut.domain.ids import RuleId, SymbolId
from taut.domain.location import ConfigPath
from taut.finding_processing.finding_processor import FindingProcessor
from taut.finding_processing.report_builder import build_run_report
from taut.loading.config_loader import (
    load_project_configuration,
)
from taut.loading.config_migration import (
    migrate_configuration_text,
    write_migrated_configuration,
)
from taut.loading.errors import PolicyConfigError
from taut.loading.inline_ignores import load_inline_ignores
from taut.loading.source_discovery import discover_sources
from taut.policy.context import PolicyContext
from taut.policy.decision_digest import build_decision_digest
from taut.policy.engine import PolicyEngine
from taut.policy.packs import load_fact_provider, load_rule_pack
from taut.policy.registry import RuleRegistry
from taut.policy.rules import builtin_rule_registry
from taut.reporting.json import render_configuration_error_json, render_json
from taut.reporting.text import DEFAULT_TEXT_WIDTH, MINIMUM_TEXT_WIDTH, render_text

_ASYNC_SESSION_TYPE = SymbolId("sqlalchemy.ext.asyncio.AsyncSession")
_MINIMUM_PARALLEL_SOURCES = 100
_MAXIMUM_ANALYSIS_WORKERS = 4


@dataclass(frozen=True)
class CheckOptions:
    project_root: Path
    config_path: ConfigPath | None
    output_format: str
    show_inactive: bool
    verbose: bool
    color: str
    width: int | None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="taut")
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("check", help="Python 백엔드 정책을 검사합니다.")
    check.add_argument("project_root", nargs="?", default=".")
    check.add_argument(
        "--config",
        help="별도 TOML 설정 파일을 사용합니다. 기본값은 pyproject.toml 자동 탐색입니다.",
    )
    check.add_argument("--format", choices=("text", "json"), default="text")
    check.add_argument("--show-inactive", action="store_true")
    check.add_argument("-v", "--verbose", action="store_true")
    check.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    check.add_argument(
        "--width",
        type=int,
        help="출력 줄 너비입니다. 기본값은 터미널 너비이며 최소 60입니다.",
    )
    rules = subparsers.add_parser("rules", help="내장 규칙 목록과 설명을 보여 줍니다.")
    rules.add_argument("rule_id", nargs="?")
    config = subparsers.add_parser("config", help="설정 파일을 검사합니다.")
    config_commands = config.add_subparsers(dest="config_command", required=True)
    validate = config_commands.add_parser("validate", help="설정 파일만 검사합니다.")
    validate.add_argument("project_root", nargs="?", default=".")
    validate.add_argument(
        "--config",
        help="별도 TOML 설정 파일을 사용합니다. 기본값은 pyproject.toml 자동 탐색입니다.",
    )
    migrate = config_commands.add_parser("migrate", help="v1/v2 설정을 v3로 변환합니다.")
    migrate.add_argument("project_root", nargs="?", default=".")
    migrate.add_argument("--config", help="변환할 별도 TOML 설정 파일입니다.")
    migrate.add_argument("--output", help="변환 결과를 저장할 새 파일입니다.")
    migrate.add_argument("--force", action="store_true", help="기존 출력 파일을 덮어씁니다.")
    explain = config_commands.add_parser("explain", help="실제로 적용되는 설정을 설명합니다.")
    explain.add_argument("project_root", nargs="?", default=".")
    explain.add_argument("--config", help="설명할 별도 TOML 설정 파일입니다.")
    explain.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def _check_options(namespace: argparse.Namespace) -> CheckOptions:
    root_value = namespace.project_root
    config_value = namespace.config
    format_value = namespace.format
    show_inactive = namespace.show_inactive
    verbose = namespace.verbose
    color = namespace.color
    width = namespace.width
    if not isinstance(root_value, str):
        raise ValueError("project_root must be a string")
    if config_value is not None and not isinstance(config_value, str):
        raise ValueError("config must be a string")
    if not isinstance(format_value, str):
        raise ValueError("format must be a string")
    if not isinstance(show_inactive, bool):
        raise ValueError("show_inactive must be a boolean")
    if not isinstance(verbose, bool):
        raise ValueError("verbose must be a boolean")
    if not isinstance(color, str):
        raise ValueError("color must be a string")
    if width is not None and (not isinstance(width, int) or width < MINIMUM_TEXT_WIDTH):
        raise ValueError(f"width must be at least {MINIMUM_TEXT_WIDTH}")
    return CheckOptions(
        project_root=Path(root_value).resolve(),
        config_path=ConfigPath(config_value) if config_value is not None else None,
        output_format=format_value,
        show_inactive=show_inactive,
        verbose=verbose,
        color=color,
        width=width,
    )


def run_check(options: CheckOptions) -> int:
    config = load_project_configuration(options.project_root, options.config_path)
    discovery = discover_sources(options.project_root, config)
    adapter = PythonAstAdapter()
    context_manager_providers = {
        ContextManagerProvider(symbol, _ASYNC_SESSION_TYPE)
        for symbol in config.policy.transaction_session_providers
    }
    context_manager_providers.update(
        ContextManagerProvider(symbol, symbol)
        for symbol in config.policy.boundaries.http_timeout_calls
    )
    request = AnalysisRequest(
        project_root=ProjectRoot(options.project_root),
        sources=discovery.sources,
        language=LanguageSettings(),
        resolver=ResolverSettings(
            source_roots=config.source_roots,
            context_manager_providers=tuple(sorted(context_manager_providers)),
        ),
        adapter_versions=FrozenMap(((adapter.identity.name, adapter.identity.version),)),
    )
    snapshot = ProjectAnalyzer(adapter).analyze(
        request,
        workers=_analysis_workers(len(request.sources)),
    )
    providers = tuple(load_fact_provider(provider_id) for provider_id in config.providers)
    snapshot = apply_fact_providers(snapshot, providers)
    classifications = config.manifest.classify(snapshot)
    validate_classification_for_policy(classifications, config.policy)
    model = SnapshotSemanticModel(snapshot)
    context = PolicyContext(
        model=model,
        classification=classifications,
        effects=EffectResolver(),
        catalog=config.catalog,
        policy=config.policy,
    )
    packs = tuple(load_rule_pack(pack_id) for pack_id in config.packs)
    registry = RuleRegistry.build(
        definition for pack in packs for definition in pack.registry.definitions.values()
    )
    ignore_result = load_inline_ignores(
        discovery.sources,
        frozenset(registry.definitions),
    )
    policy_result = PolicyEngine(registry).run(context)
    help_by_rule = FrozenMap(
        (rule_id, definition.help) for rule_id, definition in registry.definitions.items()
    )
    processing = FindingProcessor().process(
        findings=policy_result.findings,
        policy=config.policy,
        help_by_rule=help_by_rule,
        ignores=ignore_result.directives,
    )
    report = build_run_report(
        snapshot=snapshot,
        engine_version=__version__,
        decision_digest=build_decision_digest(config, registry, adapter.identity, packs, providers),
        diagnostics=processing.diagnostics,
        engine_issues=(
            *discovery.issues,
            *snapshot.issues,
            *policy_result.engine_issues,
            *processing.engine_issues,
            *ignore_result.issues,
        ),
        coverage=policy_result.coverage,
        ignore_audit=processing.ignore_audit,
    )
    if options.output_format == "json":
        print(render_json(report))
    else:
        print(
            render_text(
                report,
                show_inactive=options.show_inactive,
                verbose=options.verbose,
                color=_use_color(options.color),
                width=_output_width(options.width),
            )
        )
    return report.exit_decision.code


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    raw_arguments = tuple(argv) if argv is not None else tuple(sys.argv[1:])
    try:
        namespace = parser.parse_args(argv)
        command = namespace.command
        if command == "rules":
            registry = builtin_rule_registry()
            selected = namespace.rule_id
            if selected is None:
                for rule_id, definition in registry.definitions.items():
                    print(f"{rule_id.value}\t{definition.default_level.value}\t{definition.title}")
                return 0
            if not isinstance(selected, str):
                raise ValueError("rule_id must be a string")
            selected_definition = registry.definitions.get(RuleId(selected))
            if selected_definition is None:
                raise PolicyConfigError(f"unknown rule: {selected}")
            zones = ", ".join(sorted(zone.value for zone in selected_definition.applies_to_zones))
            print(f"{selected_definition.id.value} {selected_definition.title}")
            print(f"강도: {selected_definition.default_level.value}")
            print(f"적용 영역: {zones}")
            print(f"수정 방법: {selected_definition.help}")
            return 0
        if command == "config":
            root = Path(namespace.project_root).resolve()
            config_path = ConfigPath(namespace.config) if namespace.config is not None else None
            if namespace.config_command == "migrate":
                _, migrated = migrate_configuration_text(root, config_path)
                output = namespace.output
                if output is None:
                    print(migrated, end="")
                else:
                    write_migrated_configuration(
                        Path(output).resolve(), migrated, force=bool(namespace.force)
                    )
                return 0
            if namespace.config_command == "explain":
                loaded = load_project_configuration(root, config_path)
                payload = {
                    "schema_version": loaded.schema_version,
                    "configuration_digest": loaded.digest(),
                    "packs": loaded.packs,
                    "providers": loaded.providers,
                    "source_roots": tuple(path.value for path in loaded.source_roots),
                    "roles": tuple(
                        {
                            "name": role.role.value,
                            "include": role.patterns,
                            "exclude": role.exclude,
                            "priority": role.priority,
                        }
                        for role in loaded.manifest.roles
                    ),
                    "default_zone": loaded.manifest.default_zone.value,
                    "default_max_lines": loaded.policy.default_max_lines,
                }
                if namespace.format == "json":
                    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
                else:
                    print(f"스키마: v{loaded.schema_version}")
                    print(f"규칙 팩: {', '.join(loaded.packs)}")
                    print(f"분석 provider: {', '.join(loaded.providers) or '(없음)'}")
                    print(f"기본 영역: {loaded.manifest.default_zone.value}")
                    print(f"최대 파일 길이: {loaded.policy.default_max_lines}")
                    print(f"설정 digest: {loaded.digest()}")
                return 0
            if namespace.config_command != "validate":
                parser.error("unknown config command")
            config = load_project_configuration(root, config_path)
            print(f"설정 정상: {config.manifest.source.path} ({config.digest()})")
            return 0
        if command != "check":
            parser.error("unknown command")
        return run_check(_check_options(namespace))
    except (PolicyConfigError, ValueError, OSError) as error:
        message = f"configuration error: {error}"
        if _requests_json(raw_arguments):
            print(render_configuration_error_json(__version__, message))
        else:
            print(message, file=sys.stderr)
        return 2


def _requests_json(arguments: tuple[str, ...]) -> bool:
    return "--format=json" in arguments or any(
        argument == "--format" and index + 1 < len(arguments) and arguments[index + 1] == "json"
        for index, argument in enumerate(arguments)
    )


def _use_color(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never":
        return False
    return sys.stdout.isatty()


def _output_width(configured: int | None) -> int:
    if configured is not None:
        return configured
    if not sys.stdout.isatty():
        return DEFAULT_TEXT_WIDTH
    terminal_width = shutil.get_terminal_size(fallback=(DEFAULT_TEXT_WIDTH, 24)).columns
    return max(terminal_width, MINIMUM_TEXT_WIDTH)


def _analysis_workers(source_count: int) -> int:
    if source_count < _MINIMUM_PARALLEL_SOURCES:
        return 1
    available = os.cpu_count() or 1
    return max(1, min(available, _MAXIMUM_ANALYSIS_WORKERS, source_count))


if __name__ == "__main__":
    raise SystemExit(main())
