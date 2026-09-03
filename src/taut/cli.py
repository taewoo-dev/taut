from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from collections.abc import Generator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import replace
from pathlib import Path

from taut import __version__
from taut.analysis.contracts import SourceInput
from taut.cache import CacheStore
from taut.cache.authenticated import load_user_signing_key
from taut.cache.store import ReportEnvelope
from taut.check_runtime import CheckRuntime, prepare_check_runtime
from taut.check_service import CheckRequest, CheckResult, run_check_request
from taut.cli_assurance import run_audit, run_config_schema, run_init, run_rules
from taut.cli_workspace import (
    CheckOptions,
    configuration_payload,
    run_workspace_check,
    run_workspace_config,
)
from taut.daemon_client import (
    DaemonError,
    check_daemon,
    daemon_status,
    restart_daemon,
    start_daemon,
    stop_daemon,
)
from taut.domain.location import ConfigPath
from taut.loading.config_migration import (
    migrate_configuration_text,
    write_migrated_configuration,
)
from taut.loading.errors import PolicyConfigError
from taut.loading.source_discovery import discover_sources
from taut.reporting.json import render_configuration_error_json
from taut.reporting.text import DEFAULT_TEXT_WIDTH, MINIMUM_TEXT_WIDTH
from taut.workspace import load_workspace


@contextmanager
def _cache_context(directory: Path, *, enabled: bool) -> Generator[CacheStore | None, None, None]:
    """Best-effort cache resource; cache failures never affect check output."""
    if not enabled:
        yield None
        return
    store = CacheStore(directory, signing_key=load_user_signing_key())
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
    parser = argparse.ArgumentParser(
        prog="taut",
        description="Python backend architecture policy and assurance checks.",
        epilog="시작: taut init . --format json  |  CI: taut check . --format json",
    )
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
    check.add_argument("--daemon", choices=("auto", "never", "required"), default="never")
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
    rules.add_argument("--format", choices=("text", "json"), default="text")
    init = subparsers.add_parser(
        "init", help="프로젝트를 탐색하고 검토 가능한 strict 설정 제안을 만듭니다."
    )
    init.add_argument("project_root", nargs="?", default=".")
    init.add_argument("--config", default="pyproject.toml", help="저장할 설정 경로입니다.")
    init.add_argument("--answers", help="init JSON 답변 파일이며 -는 stdin입니다.")
    init.add_argument("--write", action="store_true", help="모든 결정이 끝난 설정만 저장합니다.")
    init.add_argument("--format", choices=("text", "json"), default="text")
    audit = subparsers.add_parser(
        "audit", help="소스·역할·기능별 strict assurance 완전성만 검사합니다."
    )
    audit.add_argument("project_root", nargs="?", default=".")
    audit.add_argument("--config")
    audit.add_argument("--format", choices=("text", "json"), default="text")
    config = subparsers.add_parser("config", help="설정 파일을 검사합니다.")
    config_commands = config.add_subparsers(dest="config_command", required=True)
    validate = config_commands.add_parser("validate", help="설정 파일만 검사합니다.")
    validate.add_argument("project_root", nargs="?", default=".")
    validate.add_argument(
        "--config",
        help="별도 TOML 설정 파일을 사용합니다. 기본값은 pyproject.toml 자동 탐색입니다.",
    )
    migrate = config_commands.add_parser("migrate", help="이전 설정을 v4로 변환합니다.")
    migrate.add_argument("project_root", nargs="?", default=".")
    migrate.add_argument("--config", help="변환할 별도 TOML 설정 파일입니다.")
    migrate.add_argument("--output", help="변환 결과를 저장할 새 파일입니다.")
    migrate.add_argument("--force", action="store_true", help="기존 출력 파일을 덮어씁니다.")
    explain = config_commands.add_parser("explain", help="실제로 적용되는 설정을 설명합니다.")
    explain.add_argument("project_root", nargs="?", default=".")
    explain.add_argument("--config", help="설명할 별도 TOML 설정 파일입니다.")
    explain.add_argument("--format", choices=("text", "json"), default="text")
    schema = config_commands.add_parser(
        "schema", help="AI와 도구가 읽을 수 있는 설정 계약을 보여 줍니다."
    )
    schema.add_argument("--format", choices=("text", "json"), default="text")
    cache = subparsers.add_parser("cache", help="persistent report cache 관리")
    cache_commands = cache.add_subparsers(dest="cache_command", required=True)
    for name, help_text in (("stats", "캐시 통계"), ("clean", "캐시 비우기")):
        command_parser = cache_commands.add_parser(name, help=help_text)
        command_parser.add_argument("project_root", nargs="?", default=".")
        command_parser.add_argument("--config")
        command_parser.add_argument("--cache-dir")
    daemon = subparsers.add_parser("daemon", help="상주 분석 daemon 관리")
    daemon_commands = daemon.add_subparsers(dest="daemon_command", required=True)
    for name in ("start", "status", "stop", "restart"):
        command_parser = daemon_commands.add_parser(name)
        command_parser.add_argument("project_root", nargs="?", default=".")
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
    daemon_mode = namespace.daemon
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
    if daemon_mode not in {"auto", "never", "required"}:
        raise ValueError("daemon mode is invalid")
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
        daemon_mode=daemon_mode,
    )


def run_check(options: CheckOptions) -> int:
    workspace = load_workspace(options.project_root) if options.config_path is None else None
    if workspace is not None:
        return run_workspace_check(options, workspace, _execute_check)
    result = _execute_check(options)
    sys.stdout.buffer.write(result.stdout)
    if result.stderr:
        sys.stderr.buffer.write(result.stderr)
    return result.exit_code


def _execute_check(options: CheckOptions) -> CheckResult:
    messages: list[str] = []
    request = _check_request(options)
    if options.daemon_mode != "never":
        try:
            result = check_daemon(request)
        except (DaemonError, OSError, TimeoutError):
            if options.daemon_mode == "required":
                raise
            if options.verbose:
                messages.append("taut daemon: unavailable; using local pipeline")
        else:
            if options.verbose:
                counters = result.counters
                messages.append(
                    "taut daemon: "
                    f"reparsed={counters.reparsed_modules} "
                    f"reused={counters.reused_modules} "
                    f"evaluated={counters.recomputed_evaluations}"
                )
            return _with_messages(result, messages)
    runtime = prepare_check_runtime(options.project_root, options.config_path)
    config = runtime.config
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
            messages.append("taut cache: error")
        if cache_store is not None:
            fingerprint = _report_cache_key(runtime, request, discovery.sources)
            cache_key = fingerprint
            try:
                cached = cache_store.get_report_envelope(fingerprint)
            except Exception:
                cached = None
            if cached is not None:
                if options.verbose:
                    messages.append("taut cache: hit")
                return CheckResult(
                    cached.stdout,
                    cached.stderr + _message_bytes(messages),
                    int(cached.exit_code),
                    None,
                )
            if options.verbose:
                messages.append("taut cache: miss")
    if cache_key is None:
        result = run_check_request(request, runtime=runtime)
    else:
        with _cache_context(directory, enabled=True) as module_store:
            result = run_check_request(request, module_store, runtime)
    output_bytes = result.stdout
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
                messages.append("taut cache: error")
    return _with_messages(result, messages)


def _with_messages(result: CheckResult, messages: list[str]) -> CheckResult:
    return replace(result, stderr=result.stderr + _message_bytes(messages))


def _message_bytes(messages: list[str]) -> bytes:
    return ("" if not messages else "\n".join(messages) + "\n").encode()


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    raw_arguments = tuple(argv) if argv is not None else tuple(sys.argv[1:])
    try:
        namespace = parser.parse_args(argv)
        command = namespace.command
        if command == "init":
            return run_init(namespace)
        if command == "audit":
            return run_audit(namespace)
        if command == "rules":
            return run_rules(namespace)
        if command == "config":
            if namespace.config_command == "schema":
                return run_config_schema(namespace.format)
            root = Path(namespace.project_root).resolve()
            config_path = ConfigPath(namespace.config) if namespace.config is not None else None
            workspace = load_workspace(root) if config_path is None else None
            if workspace is not None:
                return run_workspace_config(
                    workspace, namespace.config_command, getattr(namespace, "format", "text")
                )
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
                loaded = prepare_check_runtime(root, config_path).config
                payload = configuration_payload(loaded)
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
            config = prepare_check_runtime(root, config_path).config
            print(f"설정 정상: {config.manifest.source.path} ({config.digest()})")
            return 0
        if command == "cache":
            root = Path(namespace.project_root).resolve()
            config_path = ConfigPath(namespace.config) if namespace.config is not None else None
            configured = prepare_check_runtime(root, config_path).config
            directory = (
                Path(namespace.cache_dir).resolve()
                if namespace.cache_dir
                else root / configured.cache_directory.value
            )
            if not (directory / "cache.sqlite3").exists():
                if namespace.cache_command == "clean":
                    print("캐시 삭제 완료")
                else:
                    print("모듈: 0")
                    print("리포트: 0")
                    print("바이트: 0")
                return 0
            with CacheStore(directory, signing_key=load_user_signing_key()) as store:
                if namespace.cache_command == "clean":
                    store.clean()
                    print("캐시 삭제 완료")
                else:
                    stats = store.stats()
                    print(f"모듈: {stats.module_entries}")
                    print(f"리포트: {stats.report_entries}")
                    print(f"바이트: {stats.total_bytes}")
            return 0
        if command == "daemon":
            root = Path(namespace.project_root).resolve()
            daemon_command = namespace.daemon_command
            if daemon_command == "start":
                status = start_daemon(root)
                print(f"daemon running: pid={status.pid} port={status.port}")
                return 0
            if daemon_command == "status":
                running = daemon_status(root)
                if running is None:
                    print("daemon stopped")
                    return 1
                print(f"daemon running: pid={running.pid} port={running.port}")
                return 0
            if daemon_command == "stop":
                stopped = stop_daemon(root)
                print("daemon stopped" if stopped else "daemon not running")
                return 0 if stopped else 1
            if daemon_command == "restart":
                status = restart_daemon(root)
                print(f"daemon running: pid={status.pid} port={status.port}")
                return 0
            parser.error("unknown daemon command")
        if command != "check":
            parser.error("unknown command")
        return run_check(_check_options(namespace))
    except (DaemonError, PolicyConfigError, ValueError, OSError) as error:
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


def _check_request(options: CheckOptions) -> CheckRequest:
    return CheckRequest(
        project_root=options.project_root,
        config_path=options.config_path,
        output_format=options.output_format,
        show_inactive=options.show_inactive,
        verbose=options.verbose,
        use_color=_use_color(options.color),
        width=_output_width(options.width),
    )


def _report_cache_key(
    runtime: CheckRuntime,
    request: CheckRequest,
    sources: tuple[SourceInput, ...],
) -> str:
    source_values = tuple((source.path.value, source.content_hash) for source in sources)
    payload = {
        "schema": 2,
        "engine_version": __version__,
        "decision_digest": runtime.decision_digest,
        "python_runtime": [sys.version_info.major, sys.version_info.minor],
        "project_root": str(request.project_root.resolve()),
        "config_path": runtime.config.manifest.source.path.value,
        "adapter": {
            "name": runtime.adapter.identity.name,
            "version": runtime.adapter.identity.version,
        },
        "render": {
            "format": request.output_format,
            "show_inactive": request.show_inactive,
            "verbose": request.verbose,
            "use_color": request.use_color,
            "width": request.width,
        },
        "sources": source_values,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


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
