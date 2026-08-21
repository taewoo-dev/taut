from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from collections.abc import Generator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path

from taut import __version__
from taut.cache import CacheStore
from taut.cache.store import ReportEnvelope
from taut.check_service import CheckRequest, run_check_request
from taut.domain.ids import RuleId
from taut.domain.location import ConfigPath
from taut.loading.config_loader import (
    load_project_configuration,
)
from taut.loading.config_migration import (
    migrate_configuration_text,
    write_migrated_configuration,
)
from taut.loading.errors import PolicyConfigError
from taut.loading.source_discovery import discover_sources
from taut.policy.rules import builtin_rule_registry
from taut.reporting.json import render_configuration_error_json
from taut.reporting.text import DEFAULT_TEXT_WIDTH, MINIMUM_TEXT_WIDTH


@dataclass(frozen=True)
class CheckOptions:
    project_root: Path
    config_path: ConfigPath | None
    output_format: str
    show_inactive: bool
    verbose: bool
    color: str
    width: int | None
    no_cache: bool = False
    cache_dir: Path | None = None


@contextmanager
def _cache_context(directory: Path, *, enabled: bool) -> Generator[CacheStore | None, None, None]:
    """Best-effort cache resource; cache failures never affect check output."""
    if not enabled:
        yield None
        return
    store = CacheStore(directory)
    try:
        store.__enter__()
    except Exception:
        yield None
        return
    try:
        yield store
    finally:
        with suppress(Exception):
            store.__exit__(None, None, None)


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
    check.add_argument("--no-cache", action="store_true")
    check.add_argument("--cache-dir")
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
    cache = subparsers.add_parser("cache", help="persistent report cache 관리")
    cache_commands = cache.add_subparsers(dest="cache_command", required=True)
    for name, help_text in (("stats", "캐시 통계"), ("clean", "캐시 비우기")):
        command_parser = cache_commands.add_parser(name, help=help_text)
        command_parser.add_argument("project_root", nargs="?", default=".")
        command_parser.add_argument("--cache-dir")
    return parser


def _check_options(namespace: argparse.Namespace) -> CheckOptions:
    root_value = namespace.project_root
    config_value = namespace.config
    format_value = namespace.format
    show_inactive = namespace.show_inactive
    verbose = namespace.verbose
    color = namespace.color
    width = namespace.width
    no_cache = namespace.no_cache
    cache_dir = Path(namespace.cache_dir).resolve() if namespace.cache_dir else None
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
        no_cache=no_cache,
        cache_dir=cache_dir,
    )


def run_check(options: CheckOptions) -> int:
    config = load_project_configuration(options.project_root, options.config_path)
    discovery = discover_sources(options.project_root, config)
    cache_key = None
    directory = options.cache_dir or (options.project_root / config.cache_directory.value)
    with _cache_context(
        directory, enabled=not options.no_cache and config.cache_enabled
    ) as cache_store:
        if (
            cache_store is None
            and not options.no_cache
            and config.cache_enabled
            and options.verbose
        ):
            print("taut cache: error", file=sys.stderr)
        if cache_store is not None:
            fingerprint = hashlib.sha256(
                (
                    __version__
                    + "|report-schema:1|"
                    + config.digest()
                    + options.output_format
                    + str(options.show_inactive)
                    + str(options.verbose)
                    + options.color
                    + str(options.width)
                    + "python-target:3.11|adapter:python:1|"
                    + "|".join(f"{s.path.value}:{s.content_hash}" for s in discovery.sources)
                ).encode()
            ).hexdigest()
            cache_key = fingerprint
            try:
                cached = cache_store.get_report_envelope(fingerprint)
            except Exception:
                cached = None
            if cached is not None:
                sys.stdout.buffer.write(cached.stdout)
                if cached.stderr:
                    sys.stderr.buffer.write(cached.stderr)
                if options.verbose:
                    print("taut cache: hit", file=sys.stderr)
                return int(cached.exit_code)
            if options.verbose:
                print("taut cache: miss", file=sys.stderr)
    result = run_check_request(
        CheckRequest(
            project_root=options.project_root,
            config_path=options.config_path,
            output_format=options.output_format,
            show_inactive=options.show_inactive,
            verbose=options.verbose,
            use_color=_use_color(options.color),
            width=_output_width(options.width),
        )
    )
    output_bytes = result.stdout
    sys.stdout.buffer.write(result.stdout)
    if result.stderr:
        sys.stderr.buffer.write(result.stderr)
    if cache_key is not None:
        try:
            with _cache_context(directory, enabled=True) as write_store:
                if write_store is not None:
                    write_store.put_report_envelope(
                        cache_key,
                        ReportEnvelope(
                            1,
                            cache_key,
                            output_bytes,
                            b"",
                            result.exit_code,
                            {
                                "format": options.output_format,
                                "show_inactive": str(options.show_inactive),
                                "verbose": str(options.verbose),
                                "color": options.color,
                                "width": str(options.width),
                            },
                        ),
                    )
        except Exception:
            if options.verbose:
                print("taut cache: error", file=sys.stderr)
    return result.exit_code


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
        if command == "cache":
            root = Path(namespace.project_root).resolve()
            directory = (
                Path(namespace.cache_dir).resolve() if namespace.cache_dir else root / ".taut_cache"
            )
            with CacheStore(directory) as store:
                if namespace.cache_command == "clean":
                    store.clean()
                    print("캐시 삭제 완료")
                else:
                    stats = store.stats()
                    print(f"모듈: {stats.module_entries}")
                    print(f"리포트: {stats.report_entries}")
                    print(f"바이트: {stats.total_bytes}")
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


if __name__ == "__main__":
    raise SystemExit(main())
