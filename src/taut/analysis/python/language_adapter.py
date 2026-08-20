from __future__ import annotations

import ast
from concurrent.futures import ProcessPoolExecutor
from itertools import repeat

from taut.analysis.contracts import (
    AdapterIdentity,
    ModuleAnalysisResult,
    ResolverSettings,
    SourceInput,
)
from taut.analysis.module_analysis import ModuleAnalysis
from taut.analysis.python.adapter import PythonFactExtractor
from taut.analysis.python.failed_analysis import failed_facts
from taut.domain.facts import AnalysisStage
from taut.domain.issues import EngineIssue, EngineIssueKind
from taut.domain.location import SourceRange


class PythonAstAdapter:
    identity = AdapterIdentity(name="python-ast", version="6")

    def analyze_module(
        self,
        source: SourceInput,
        resolver: ResolverSettings | None = None,
    ) -> ModuleAnalysisResult:
        lifecycle = ModuleAnalysis()
        resolver_settings = resolver or ResolverSettings()
        try:
            tree = ast.parse(source.content, filename=source.path.value, type_comments=True)
            lifecycle.advance(AnalysisStage.PARSED)
            lifecycle.advance(AnalysisStage.INDEXED)
            lifecycle.advance(AnalysisStage.RESOLVED)
            facts = PythonFactExtractor(source, resolver_settings).extract(tree)
            lifecycle.advance(AnalysisStage.FACTS_READY)
            return ModuleAnalysisResult(facts=facts, issues=())
        except SyntaxError as error:
            lifecycle.fail()
            line = max((error.lineno or 1) - 1, 0)
            column = max((error.offset or 1) - 1, 0)
            location = SourceRange(source.path, line, column, line, column)
            issue = EngineIssue(
                code="PY_PARSE_001",
                kind=EngineIssueKind.PARSE_FAILURE,
                message="Python 문법을 해석하지 못했습니다.",
                location=location,
                cause=error.msg,
            )
            return ModuleAnalysisResult(facts=failed_facts(source), issues=(issue,))
        except Exception as error:  # analyzer failures must become explicit issues
            lifecycle.fail()
            issue = EngineIssue(
                code="PY_ANALYSIS_001",
                kind=EngineIssueKind.ANALYSIS_FAILURE,
                message=f"Python 파일 분석을 완료하지 못했습니다: {source.path.value}",
                location=SourceRange(source.path, 0, 0, 0, 0),
                cause=error.__class__.__name__,
            )
            return ModuleAnalysisResult(facts=failed_facts(source), issues=(issue,))

    def analyze_modules(
        self,
        sources: tuple[SourceInput, ...],
        resolver: ResolverSettings,
        workers: int,
    ) -> tuple[ModuleAnalysisResult, ...]:
        if workers == 1:
            return tuple(self.analyze_module(source, resolver) for source in sources)
        chunk_size = max(1, len(sources) // (workers * 16))
        with ProcessPoolExecutor(max_workers=workers) as executor:
            return tuple(
                executor.map(
                    _analyze_python_module,
                    sources,
                    repeat(resolver),
                    chunksize=chunk_size,
                )
            )


def _analyze_python_module(
    source: SourceInput,
    resolver: ResolverSettings,
) -> ModuleAnalysisResult:
    return PythonAstAdapter().analyze_module(source, resolver)
