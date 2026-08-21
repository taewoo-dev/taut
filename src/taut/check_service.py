"""Canonical, reusable check pipeline.

The service deliberately returns bytes rather than printing.  This keeps the
daemon and command line front ends on exactly the same rendering path.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from taut.analysis.python.language_adapter import PythonAstAdapter
from taut.domain.location import ConfigPath
from taut.incremental import IncrementalProjectAnalyzer
from taut.loading.config_loader import load_project_configuration
from taut.policy.engine import IncrementalPolicyResult


@dataclass(frozen=True)
class CheckRequest:
    project_root: Path
    config_path: ConfigPath | None = None
    output_format: str = "text"
    show_inactive: bool = False
    verbose: bool = False
    color: str = "auto"
    width: int | None = None


@dataclass(frozen=True)
class StageTiming:
    name: str
    milliseconds: float


@dataclass(frozen=True)
class CheckCounters:
    reparsed_modules: int = 0
    reused_modules: int = 0
    recomputed_providers: int = 0
    reused_providers: int = 0
    recomputed_evaluations: int = 0
    reused_evaluations: int = 0


@dataclass(frozen=True)
class CheckResult:
    stdout: bytes
    stderr: bytes
    exit_code: int
    findings: tuple[object, ...] = ()
    coverage: object | None = None
    issues: tuple[object, ...] = ()
    timings: tuple[StageTiming, ...] = ()
    counters: CheckCounters = field(default_factory=CheckCounters)


class ResidentCheckSession:
    """Stateful pipeline owner for daemon integrations.

    ``runner`` is injected by the CLI adapter; keeping the state machine here
    makes lifecycle and identity semantics testable without a process.
    """
    def __init__(
        self,
        project_root: Path,
        runner: Callable[[CheckRequest, ResidentCheckSession], CheckResult],
    ):
        self.project_root = project_root.resolve()
        self._runner = runner
        self._identity: tuple[object, ...] | None = None
        self._last: CheckResult | None = None
        self._closed = False
        self._analyzer = IncrementalProjectAnalyzer(PythonAstAdapter())
        self.prior_provider_snapshot = None
        self.prior_policy_context = None
        self.prior_policy_result: IncrementalPolicyResult | None = None

    def check(self, request: CheckRequest) -> CheckResult:
        if self._closed:
            raise RuntimeError("resident check session is closed")
        root = request.project_root.resolve()
        if root != self.project_root:
            raise ValueError("request project root differs from session root")
        config = load_project_configuration(root, request.config_path)  # identity probe
        identity = (root, config.digest(), PythonAstAdapter().identity)
        if identity != self._identity:
            self.reset()
            self._identity = identity
        result = self._runner(request, self)
        self._last = result
        return result

    def reset(self) -> None:
        self._identity = None
        self._last = None
        self.prior_provider_snapshot = None
        self.prior_policy_context = None
        self.prior_policy_result = None
        self._analyzer = IncrementalProjectAnalyzer(PythonAstAdapter())

    def close(self) -> None:
        self.reset()
        self._closed = True
