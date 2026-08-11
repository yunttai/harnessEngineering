from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class StringEnum(str, Enum):
    """String-valued enum compatible with every supported Python runtime."""

    def __str__(self) -> str:
        return str(self.value)


class Severity(StringEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class FindingStatus(StringEnum):
    DETECTED = "DETECTED"
    ANALYZED = "ANALYZED"
    PATCH_GENERATED = "PATCH_GENERATED"
    VERIFIED = "VERIFIED"
    APPLIED = "APPLIED"
    NEEDS_HUMAN_REVIEW = "NEEDS_HUMAN_REVIEW"
    FAILED = "FAILED"


class Exploitability(StringEnum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    UNCERTAIN = "UNCERTAIN"
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"


class StageStatus(StringEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


class RunState(StringEnum):
    CREATED = "CREATED"
    DETECTING = "DETECTING"
    DETECTED = "DETECTED"
    ANALYZING = "ANALYZING"
    PATCH_GENERATING = "PATCH_GENERATING"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    APPLIED = "APPLIED"
    PR_CREATED = "PR_CREATED"
    DEPLOYED = "DEPLOYED"
    DETECTION_FAILED = "DETECTION_FAILED"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"
    PATCH_FAILED = "PATCH_FAILED"
    BUILD_FAILED = "BUILD_FAILED"
    TEST_FAILED = "TEST_FAILED"
    SECURITY_TEST_FAILED = "SECURITY_TEST_FAILED"
    NEEDS_HUMAN_REVIEW = "NEEDS_HUMAN_REVIEW"
    PUBLISH_FAILED = "PUBLISH_FAILED"
    DEPLOY_FAILED = "DEPLOY_FAILED"
    FAILED = "FAILED"


class Evidence(BaseModel):
    model_config = ConfigDict(extra="allow")

    scanner: str
    rule_id: str | None = None
    message: str | None = None
    source: str | None = None
    sink: str | None = None
    file: str
    line: int = Field(ge=1)
    column: int | None = Field(default=None, ge=1)
    raw_excerpt: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    fingerprint: str
    type: str
    cwe: str
    severity: Severity
    file: str
    line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)
    function: str | None = None
    source: str | None = None
    sink: str | None = None
    scanner: str
    rule_id: str | None = None
    message: str
    evidence: list[Evidence] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    status: FindingStatus = FindingStatus.DETECTED

    @field_validator("file")
    @classmethod
    def relative_file(cls, value: str) -> str:
        normalized = value.replace("\\", "/")
        if normalized.startswith("/") or normalized.startswith("../") or "/../" in normalized:
            raise ValueError("finding file must be target-relative")
        return normalized


class CodeContext(BaseModel):
    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    snippet: str
    function: str | None = None


class AnalysisResult(BaseModel):
    finding_id: str
    cwe: str
    root_cause: str
    exploitability: Exploitability
    confidence: float = Field(ge=0.0, le=1.0)
    source: str | None = None
    sink: str | None = None
    existing_validation: list[str] = Field(default_factory=list)
    recommended_fix: str
    forbidden_fixes: list[str] = Field(default_factory=list)
    required_tests: list[str] = Field(default_factory=list)
    context: CodeContext
    notes: list[str] = Field(default_factory=list)


class TextEdit(BaseModel):
    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    replacement: str
    original_sha256: str

    @field_validator("end_line")
    @classmethod
    def valid_range(cls, value: int, info: Any) -> int:
        start = info.data.get("start_line")
        if start is not None and value < start:
            raise ValueError("end_line must be >= start_line")
        return value


class PatchCandidate(BaseModel):
    candidate_id: str
    finding_id: str
    title: str
    description: str
    rationale: str
    expected_security_effect: str
    edits: list[TextEdit]
    unified_diff: str
    changed_files: list[str]
    changed_lines: int = Field(ge=0)
    provider: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class StageResult(BaseModel):
    name: str
    status: StageStatus
    command: list[str] | None = None
    exit_code: int | None = None
    duration_ms: int = Field(default=0, ge=0)
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    reason: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class PatchScore(BaseModel):
    security_test: int = Field(ge=0, le=40)
    regression_test: int = Field(ge=0, le=30)
    code_change_size: int = Field(ge=0, le=15)
    build_stability: int = Field(ge=0, le=10)
    coding_style: int = Field(ge=0, le=5)

    @property
    def total(self) -> int:
        return (
            self.security_test
            + self.regression_test
            + self.code_change_size
            + self.build_stability
            + self.coding_style
        )


class VerificationReport(BaseModel):
    candidate_id: str
    finding_id: str
    build: StageResult
    functional_test: StageResult
    security_rescan: StageResult
    exploit_test: StageResult
    score: PatchScore
    eligible: bool
    confidence: str
    rejection_reasons: list[str] = Field(default_factory=list)
    sandbox_kind: str = "local-copy"
    created_at: datetime = Field(default_factory=utc_now)


class CandidateEvaluation(BaseModel):
    candidate: PatchCandidate
    verification: VerificationReport


class PatchFeedback(BaseModel):
    """Machine-readable failed verification evidence for a later patch attempt."""

    attempt: int = Field(ge=1)
    candidate_id: str
    stage: str
    status: StageStatus
    reason: str | None = None
    command: list[str] | None = None
    exit_code: int | None = None
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    artifact: str | None = None


class PullRequestRequest(BaseModel):
    repository: str
    head: str
    base: str
    title: str
    body: str
    draft: bool = True

    @field_validator("repository")
    @classmethod
    def valid_repository(cls, value: str) -> str:
        parts = value.split("/")
        if len(parts) != 2 or not all(parts):
            raise ValueError("repository must be owner/name")
        return value


class PullRequestResult(BaseModel):
    number: int = Field(ge=1)
    url: str
    state: str
    draft: bool
    head: str
    base: str


class PublishingResult(BaseModel):
    base_sha: str
    branch: str
    commit_sha: str | None = None
    pushed: bool = False
    pull_request: PullRequestResult | None = None


class DeploymentPhase(StringEnum):
    STAGING = "STAGING"
    CANARY = "CANARY"
    ROLLBACK = "ROLLBACK"


class DeploymentResult(BaseModel):
    phase: DeploymentPhase
    status: StageStatus
    command: list[str]
    exit_code: int | None = None
    duration_ms: int = Field(default=0, ge=0)
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    reason: str | None = None


class RunMetrics(BaseModel):
    detection_precision: float | None = None
    patch_success_rate: float | None = None
    security_fix_rate: float | None = None
    regression_rate: float | None = None
    exploit_mitigation_rate: float | None = None
    autonomous_patch_rate: float | None = None
    average_changed_lines: float | None = None
    average_retry_count: float | None = None
    verification_skipped_ratio: float | None = None


class FindingOutcome(BaseModel):
    finding: Finding
    analysis: AnalysisResult | None = None
    evaluations: list[CandidateEvaluation] = Field(default_factory=list)
    selected_candidate_id: str | None = None
    applied: bool = False
    status: FindingStatus
    reason: str | None = None


class StateEvent(BaseModel):
    state: RunState
    timestamp: datetime = Field(default_factory=utc_now)
    message: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class RunReport(BaseModel):
    run_id: str
    target: str
    config_path: str
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    state: RunState = RunState.CREATED
    events: list[StateEvent] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    outcomes: list[FindingOutcome] = Field(default_factory=list)
    scanner_errors: list[str] = Field(default_factory=list)
    pull_request: PullRequestResult | None = None
    deployments: list[DeploymentResult] = Field(default_factory=list)
    metrics: RunMetrics = Field(default_factory=RunMetrics)
    artifact_dir: str | None = None
    dry_run: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)

    def transition(self, state: RunState, message: str, **metadata: Any) -> None:
        self.state = state
        self.events.append(StateEvent(state=state, message=message, metadata=metadata))
