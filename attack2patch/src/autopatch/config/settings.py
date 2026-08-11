from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class ScopeSettings(BaseModel):
    local_paths_only: bool = True
    authorized_targets: list[str] = Field(default_factory=list)
    excluded_directories: list[str] = Field(default_factory=list)
    max_file_bytes: int = Field(default=1_048_576, ge=1)


class AutonomySettings(BaseModel):
    apply_patch: bool = True
    execute_tests: bool = False
    create_branch: bool = True
    create_commit: bool = True
    push_branch: bool = True
    create_pull_request: bool = False
    execute_dast: bool = False
    deploy: bool = False
    max_patch_attempts: int = Field(default=3, ge=1, le=10)
    require_clean_git_tree: bool = True


class ScannerConfig(BaseModel):
    name: str
    enabled: bool | Literal["auto"] = True
    required: bool = False
    timeout_seconds: int = Field(default=180, ge=1)
    config: str | None = None
    execution: Literal["auto", "native", "docker"] = "auto"
    docker_image: str | None = None
    docker_network: Literal["none", "bridge"] = "none"

    @field_validator("docker_image")
    @classmethod
    def pinned_docker_image(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", normalized) is None:
            raise ValueError("scanner docker_image must be pinned to a sha256 digest")
        return normalized

    @model_validator(mode="after")
    def docker_execution_requires_image(self) -> ScannerConfig:
        if self.execution == "docker" and self.docker_image is None:
            raise ValueError("docker scanner execution requires docker_image")
        return self


class DetectionSettings(BaseModel):
    fail_on_required_scanner_error: bool = True
    scanners: list[ScannerConfig] = Field(default_factory=list)


class VerificationSettings(BaseModel):
    build_timeout_seconds: int = Field(default=120, ge=1)
    test_timeout_seconds: int = Field(default=300, ge=1)
    scanner_timeout_seconds: int = Field(default=180, ge=1)
    exploit_timeout_seconds: int = Field(default=60, ge=1)
    execute_project_tests: bool = False
    execute_project_security_tests: bool = False
    project_test_command: list[str] | None = None
    require_build_pass: bool = True
    require_regression_not_failed: bool = True
    require_security_rescan_pass: bool = True
    require_exploit_not_failed: bool = True
    require_differential_exploit: bool = False

    @field_validator("project_test_command")
    @classmethod
    def valid_project_test_command(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        if not value or any(not item.strip() or "\x00" in item for item in value):
            raise ValueError("verification project test command must be non-empty and NUL-free")
        return value


class SandboxSettings(BaseModel):
    provider: Literal["local-copy", "docker"] = "local-copy"
    docker_executable: str = "docker"
    image: str = (
        "python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36"
    )
    allow_image_pull: bool = False
    cpu_limit: float = Field(default=1.0, gt=0, le=64)
    memory_mb: int = Field(default=512, ge=64, le=131_072)
    pids_limit: int = Field(default=256, ge=16, le=65_536)
    network_mode: Literal["none"] = "none"
    read_only_rootfs: bool = True
    tmpfs_mb: int = Field(default=128, ge=16, le=4096)
    user: str | None = None
    cleanup_timeout_seconds: int = Field(default=30, ge=1, le=300)

    @field_validator("docker_executable", "user")
    @classmethod
    def safe_container_value(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized or "\x00" in normalized:
            raise ValueError("sandbox values must be non-empty and NUL-free")
        return normalized

    @field_validator("image")
    @classmethod
    def safe_image(cls, value: str) -> str:
        normalized = value.strip()
        if (
            not normalized
            or normalized.startswith("-")
            or "\x00" in normalized
            or any(character.isspace() for character in normalized)
        ):
            raise ValueError("sandbox image must be a Docker image reference")
        if re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", normalized) is None:
            raise ValueError("sandbox image must be pinned to a sha256 digest")
        return normalized


class PatchingSettings(BaseModel):
    supported_cwes: list[str] = Field(
        default_factory=lambda: ["CWE-22", "CWE-78", "CWE-89", "CWE-502"]
    )
    max_candidates_per_finding: int = Field(default=3, ge=1, le=10)
    max_changed_lines: int = Field(default=80, ge=1)
    prefer_minimal_diff: bool = True


class LlmSettings(BaseModel):
    enabled: bool = True
    provider: Literal["codex", "opencode", "claude"] = "codex"
    executable: str | None = None
    model: str | None = None
    timeout_seconds: int = Field(default=120, ge=1)
    max_prompt_chars: int = Field(default=100_000, ge=1_000, le=1_000_000)
    max_output_chars: int = Field(default=200_000, ge=10_000, le=2_000_000)
    use_for_analysis: bool = False
    use_for_patching: bool = True

    @field_validator("executable", "model")
    @classmethod
    def valid_optional_cli_value(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized or "\x00" in normalized:
            raise ValueError("LLM CLI executable/model must be a non-empty value without NUL")
        return normalized


class GitHubAppSettings(BaseModel):
    enabled: bool = False
    repository: str | None = None
    base_branch: str = "main"
    api_url: str = "https://api.github.com"
    web_url: str = "https://github.com"
    app_id_env: str = "GITHUB_APP_ID"
    installation_id_env: str = "GITHUB_APP_INSTALLATION_ID"
    private_key_env: str = "GITHUB_APP_PRIVATE_KEY"
    required_permissions: dict[str, Literal["read", "write"]] = Field(
        default_factory=lambda: {"contents": "write", "pull_requests": "write"}
    )
    timeout_seconds: int = Field(default=30, ge=1)

    @model_validator(mode="after")
    def enabled_requires_repository(self) -> GitHubAppSettings:
        if self.enabled and (
            not self.repository
            or len(self.repository.split("/")) != 2
            or not all(self.repository.split("/"))
        ):
            raise ValueError("publishing.github_app.repository must be owner/name")
        if not self.api_url.startswith("https://"):
            raise ValueError("publishing.github_app.api_url must use HTTPS")
        if not self.web_url.startswith("https://"):
            raise ValueError("publishing.github_app.web_url must use HTTPS")
        return self

    @field_validator("required_permissions")
    @classmethod
    def valid_required_permissions(
        cls,
        value: dict[str, Literal["read", "write"]],
    ) -> dict[str, Literal["read", "write"]]:
        if not value:
            raise ValueError("GitHub App smoke requires at least one permission")
        if any(not key or not key.replace("_", "").isalnum() for key in value):
            raise ValueError("GitHub App permission names must be alphanumeric snake_case")
        return value


class PublishingSettings(BaseModel):
    branch_name: str = "Attack2patch"
    draft_pull_request: bool = True
    push_remote: str = "origin"
    github_app: GitHubAppSettings = Field(default_factory=GitHubAppSettings)


class DastToolSettings(BaseModel):
    enabled: bool = False
    executable: str
    docker_image: str | None = None
    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    extra_args: list[str] = Field(default_factory=list)

    @field_validator("executable")
    @classmethod
    def safe_executable(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or "\x00" in normalized:
            raise ValueError("DAST executable must be non-empty and NUL-free")
        return normalized

    @field_validator("docker_image")
    @classmethod
    def safe_docker_image(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if (
            not normalized
            or normalized.startswith("-")
            or "\x00" in normalized
            or any(character.isspace() for character in normalized)
        ):
            raise ValueError("DAST docker_image must be a Docker image reference")
        if re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", normalized) is None:
            raise ValueError("DAST docker_image must be pinned to a sha256 digest")
        return normalized

    @field_validator("extra_args")
    @classmethod
    def safe_arguments(cls, value: list[str]) -> list[str]:
        if any("\x00" in item for item in value):
            raise ValueError("DAST arguments must be NUL-free")
        return value


class DastSettings(BaseModel):
    enabled: bool = False
    authorized_targets: list[str] = Field(default_factory=list)
    allow_sandbox_loopback: bool = False
    zap: DastToolSettings = Field(
        default_factory=lambda: DastToolSettings(
            executable="zap-baseline.py",
            docker_image=(
                "ghcr.io/zaproxy/zaproxy@sha256:"
                "781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef"
            ),
        )
    )
    nuclei: DastToolSettings = Field(
        default_factory=lambda: DastToolSettings(
            executable="nuclei",
            docker_image=(
                "projectdiscovery/nuclei@sha256:"
                "582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb"
            ),
        )
    )

    @model_validator(mode="after")
    def enabled_requires_authorized_target(self) -> DastSettings:
        if self.enabled and not self.authorized_targets and not self.allow_sandbox_loopback:
            raise ValueError(
                "DAST requires an authorized target or allow_sandbox_loopback=true"
            )
        for target in self.authorized_targets:
            parsed = urlsplit(target)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.netloc
                or parsed.username is not None
                or parsed.password is not None
                or parsed.fragment
            ):
                raise ValueError(f"unsupported DAST target: {target}")
        return self


class DeploymentSettings(BaseModel):
    enabled: bool = False
    staging_command: list[str] = Field(default_factory=list)
    canary_command: list[str] = Field(default_factory=list)
    observation_command: list[str] = Field(default_factory=list)
    promotion_command: list[str] = Field(default_factory=list)
    rollback_command: list[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=300, ge=1)
    observation_window_seconds: int = Field(default=900, ge=1, le=86_400)
    observation_interval_seconds: int = Field(default=30, ge=1, le=3_600)
    minimum_observation_passes: int = Field(default=3, ge=1, le=10_000)
    max_observation_attempts: int = Field(default=60, ge=1, le=10_000)
    rollback_runbook: str = "runbooks/rollback.md"

    @model_validator(mode="after")
    def enabled_requires_all_phases(self) -> DeploymentSettings:
        if self.enabled and not all(
            (
                self.staging_command,
                self.canary_command,
                self.observation_command,
                self.promotion_command,
                self.rollback_command,
            )
        ):
            raise ValueError(
                "deployment requires staging, canary, observation, promotion, and rollback commands"
            )
        if self.observation_interval_seconds > self.observation_window_seconds:
            raise ValueError("deployment observation interval cannot exceed its window")
        if self.max_observation_attempts < self.minimum_observation_passes:
            raise ValueError("deployment observation attempts cannot be lower than pass minimum")
        required_intervals = max(0, self.max_observation_attempts - 1)
        if required_intervals * self.observation_interval_seconds < (
            self.observation_window_seconds
        ):
            raise ValueError("deployment observation attempt bound cannot cover its window")
        return self


class LoggingSettings(BaseModel):
    level: str = "INFO"
    redact_patterns: list[str] = Field(default_factory=list)

    @field_validator("redact_patterns")
    @classmethod
    def valid_redaction_regexes(cls, values: list[str]) -> list[str]:
        for value in values:
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"invalid redaction regex {value!r}: {exc}") from exc
        return values


class HarnessSettings(BaseModel):
    version: int = 1
    project_name: str = "Attack2Patch"
    artifact_root: str = ".autopatch/runs"
    scope: ScopeSettings = Field(default_factory=ScopeSettings)
    autonomy: AutonomySettings = Field(default_factory=AutonomySettings)
    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    verification: VerificationSettings = Field(default_factory=VerificationSettings)
    sandbox: SandboxSettings = Field(default_factory=SandboxSettings)
    patching: PatchingSettings = Field(default_factory=PatchingSettings)
    llm: LlmSettings = Field(default_factory=LlmSettings)
    publishing: PublishingSettings = Field(default_factory=PublishingSettings)
    dast: DastSettings = Field(default_factory=DastSettings)
    deployment: DeploymentSettings = Field(default_factory=DeploymentSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)

    @field_validator("artifact_root")
    @classmethod
    def artifact_root_not_absolute(cls, value: str) -> str:
        if Path(value).is_absolute():
            raise ValueError("artifact_root must be relative to the harness working directory")
        return value

    @model_validator(mode="after")
    def deploy_requires_push(self) -> HarnessSettings:
        if self.autonomy.deploy and not self.autonomy.push_branch:
            raise ValueError("deploy autonomy requires push_branch autonomy")
        if self.autonomy.create_commit and not self.autonomy.create_branch:
            raise ValueError("create_commit autonomy requires create_branch autonomy")
        if self.autonomy.push_branch and not self.autonomy.create_commit:
            raise ValueError("push_branch autonomy requires create_commit autonomy")
        if self.autonomy.create_pull_request and not self.autonomy.push_branch:
            raise ValueError("create_pull_request autonomy requires push_branch autonomy")
        if self.autonomy.execute_dast and not self.dast.enabled:
            raise ValueError("execute_dast autonomy requires dast.enabled=true")
        if self.verification.require_differential_exploit and not (
            self.verification.execute_project_security_tests or self.autonomy.execute_dast
        ):
            raise ValueError(
                "differential exploit verification requires security tests or DAST autonomy"
            )
        return self


def _expand_env(value: object) -> object:
    if isinstance(value, str):
        return os.path.expandvars(value)
    if isinstance(value, list):
        return [_expand_env(item) for item in value]
    if isinstance(value, dict):
        return {key: _expand_env(item) for key, item in value.items()}
    return value


def load_settings(path: str | Path | None = None) -> HarnessSettings:
    config_path = Path(path or os.getenv("AUTOPATCH_CONFIG", "config/harness.yaml"))
    if not config_path.is_file():
        raise FileNotFoundError(f"configuration file not found: {config_path}")
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    expanded = _expand_env(raw)
    return HarnessSettings.model_validate(expanded)
