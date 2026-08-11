from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from autopatch.types import (
    AnalysisResult,
    CandidateEvaluation,
    DeploymentPhase,
    DeploymentResult,
    Finding,
    PatchCandidate,
    PatchFeedback,
    PullRequestRequest,
    PullRequestResult,
)


@runtime_checkable
class Scanner(Protocol):
    name: str
    required: bool

    def available(self) -> bool: ...

    def scan(self, target: Path) -> list[Finding]: ...


@runtime_checkable
class AnalysisProvider(Protocol):
    name: str

    def analyze(self, target: Path, finding: Finding) -> AnalysisResult: ...


@runtime_checkable
class PatchProvider(Protocol):
    name: str

    def generate(
        self,
        target: Path,
        finding: Finding,
        analysis: AnalysisResult,
        feedback: list[PatchFeedback] | None = None,
    ) -> list[PatchCandidate]: ...


@runtime_checkable
class VerificationProvider(Protocol):
    name: str

    def verify(
        self,
        target: Path,
        finding: Finding,
        candidate: PatchCandidate,
    ) -> CandidateEvaluation: ...


@runtime_checkable
class PatchApplier(Protocol):
    name: str

    def apply(self, target: Path, candidate: PatchCandidate) -> None: ...


@runtime_checkable
class GitPublisher(Protocol):
    name: str

    def is_repository(self, target: Path) -> bool: ...

    def is_clean(self, target: Path) -> bool: ...

    def current_sha(self, target: Path) -> str: ...

    def create_branch(self, target: Path, branch: str) -> None: ...

    def commit(self, target: Path, files: list[str], message: str) -> str: ...

    def push(self, target: Path, remote: str, branch: str) -> None: ...


@runtime_checkable
class PullRequestPublisher(Protocol):
    name: str

    def available(self) -> bool: ...

    def create_pull_request(self, request: PullRequestRequest) -> PullRequestResult: ...


@runtime_checkable
class DeploymentProvider(Protocol):
    name: str

    def execute(self, target: Path, phase: DeploymentPhase) -> DeploymentResult: ...
