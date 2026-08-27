from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class AssuranceEvidence:
    domain: str
    kind: str
    target: str
    path: str


@dataclass(frozen=True, order=True)
class AssuranceIssue:
    code: str
    message: str
    subject: str
    remediation: str

    def __post_init__(self) -> None:
        if not all((self.code.strip(), self.message.strip(), self.remediation.strip())):
            raise ValueError("assurance issue values cannot be empty")


@dataclass(frozen=True, order=True)
class FeatureAssurance:
    name: str
    expected: str
    detected: bool
    evidence: tuple[AssuranceEvidence, ...] = ()


@dataclass(frozen=True)
class AssuranceReport:
    discovered_python_files: int = 0
    analyzed_python_files: int = 0
    excluded_python_files: int = 0
    features: tuple[FeatureAssurance, ...] = ()
    issues: tuple[AssuranceIssue, ...] = ()
    used_assertions: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return not self.issues
