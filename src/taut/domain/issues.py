from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from taut.domain.location import ConfigLocation, SourceRange


class EngineIssueKind(StrEnum):
    INVALID_CONFIGURATION = "invalid_configuration"
    SOURCE_DISCOVERY_FAILURE = "source_discovery_failure"
    PARSE_FAILURE = "parse_failure"
    ANALYSIS_FAILURE = "analysis_failure"
    MISSING_CAPABILITY = "missing_capability"
    RULE_FAILURE = "rule_failure"
    CACHE_CORRUPTION = "cache_corruption"
    OUTPUT_FAILURE = "output_failure"


class CacheErrorCode(StrEnum):
    DECODE = "decode"
    LIMIT = "limit"
    SCHEMA = "schema"
    TYPE = "type"
    DOMAIN = "domain"


@dataclass(frozen=True, order=True)
class EngineIssue:
    code: str
    kind: EngineIssueKind
    message: str
    location: SourceRange | ConfigLocation | None
    cause: str | None = None
    retryable: bool = False

    def __post_init__(self) -> None:
        if not self.code.strip():
            raise ValueError("engine issue code cannot be empty")
        if not self.message.strip():
            raise ValueError("engine issue message cannot be empty")
