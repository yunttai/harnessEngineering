from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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


class SecurityTestCase(BaseModel):
    """A manifest command with explicit pre/post-patch expectations."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128)
    finding: str = Field(min_length=1, max_length=128)
    command: list[str] = Field(min_length=1, max_length=64)
    timeout_seconds: int = Field(default=60, ge=1, le=3600)
    expected_exit_code: int = 0
    baseline_expected_exit_code: int | None = None

    @field_validator("command")
    @classmethod
    def valid_command(cls, value: list[str]) -> list[str]:
        if any(not item.strip() or "\x00" in item or len(item) > 4096 for item in value):
            raise ValueError("security test command entries must be non-empty and NUL-free")
        return value


class ReadinessProbe(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = "/"
    expected_status: int = Field(default=200, ge=100, le=599)
    timeout_seconds: int = Field(default=30, ge=1, le=600)
    interval_ms: int = Field(default=250, ge=50, le=5000)

    @field_validator("path")
    @classmethod
    def relative_http_path(cls, value: str) -> str:
        if not value.startswith("/") or "://" in value or "\x00" in value:
            raise ValueError("readiness path must be an absolute URL path")
        return value


class ApplicationSpec(BaseModel):
    """Application process launched inside the configured Docker sandbox."""

    model_config = ConfigDict(extra="forbid")

    command: list[str] = Field(min_length=1, max_length=64)
    container_port: int = Field(ge=1, le=65535)
    readiness: ReadinessProbe = Field(default_factory=ReadinessProbe)

    @field_validator("command")
    @classmethod
    def valid_command(cls, value: list[str]) -> list[str]:
        if any(not item.strip() or "\x00" in item or len(item) > 4096 for item in value):
            raise ValueError("application command entries must be non-empty and NUL-free")
        return value


class DastTestCase(BaseModel):
    """Expected scanner delta for a finding-specific dynamic test."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128)
    finding: str = Field(min_length=1, max_length=128)
    tool: Literal["zap", "nuclei"]
    path: str = "/"
    template: str | None = None
    baseline_min_findings: int = Field(default=1, ge=0)
    patched_max_findings: int = Field(default=0, ge=0)

    @field_validator("path")
    @classmethod
    def relative_target_path(cls, value: str) -> str:
        if not value.startswith("/") or "://" in value or "\x00" in value:
            raise ValueError("DAST test path must be an absolute URL path")
        return value

    @field_validator("template")
    @classmethod
    def relative_template_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.replace("\\", "/")
        if (
            not normalized
            or normalized.startswith("/")
            or normalized.startswith("../")
            or "/../" in normalized
            or "\x00" in normalized
        ):
            raise ValueError("DAST template must be workspace-relative")
        return normalized

    @model_validator(mode="after")
    def template_is_nuclei_only(self) -> "DastTestCase":
        if self.template is not None and self.tool != "nuclei":
            raise ValueError("custom DAST templates are supported only for nuclei")
        return self


class SecurityTestManifest(BaseModel):
    """Strict boundary schema for local exploit and Docker DAST verification."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    application: ApplicationSpec | None = None
    tests: list[SecurityTestCase] = Field(default_factory=list, max_length=256)
    dast: list[DastTestCase] = Field(default_factory=list, max_length=256)

    @field_validator("tests", "dast")
    @classmethod
    def unique_ids(cls, value: list[Any]) -> list[Any]:
        ids = [item.id for item in value]
        if len(ids) != len(set(ids)):
            raise ValueError("security manifest ids must be unique within each section")
        return value

    @field_validator("dast")
    @classmethod
    def dast_requires_application(cls, value: list[DastTestCase], info: Any) -> list[DastTestCase]:
        if value and info.data.get("application") is None:
            raise ValueError("DAST tests require an application specification")
        return value


class DastFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fingerprint: str
    tool: Literal["zap", "nuclei"]
    rule_id: str
    severity: Severity
    url: str
    message: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class DastScanResult(BaseModel):
    tool: Literal["zap", "nuclei"]
    target: str
    status: StageStatus
    findings: list[DastFinding] = Field(default_factory=list)
    command: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    duration_ms: int = Field(default=0, ge=0)
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    reason: str | None = None


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
    exploit_baseline: StageResult | None = None
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


class GitHubAppSmokeResult(BaseModel):
    """Non-mutating evidence that a GitHub App installation can serve one repository."""

    status: StageStatus
    repository: str
    installation_id: str
    repository_selection: str
    permissions: dict[str, str]
    checked_at: datetime = Field(default_factory=utc_now)


class PublishingResult(BaseModel):
    base_sha: str
    branch: str
    remote: str = "origin"
    commit_sha: str | None = None
    pushed: bool = False
    pull_request: PullRequestResult | None = None


class DeploymentPhase(StringEnum):
    STAGING = "STAGING"
    CANARY = "CANARY"
    OBSERVATION = "OBSERVATION"
    PROMOTION = "PROMOTION"
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
    attempt: int | None = Field(default=None, ge=1)


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
    publishing: PublishingResult | None = None
    pull_request: PullRequestResult | None = None
    deployments: list[DeploymentResult] = Field(default_factory=list)
    metrics: RunMetrics = Field(default_factory=RunMetrics)
    artifact_dir: str | None = None
    dry_run: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)

    def transition(self, state: RunState, message: str, **metadata: Any) -> None:
        self.state = state
        self.events.append(StateEvent(state=state, message=message, metadata=metadata))
