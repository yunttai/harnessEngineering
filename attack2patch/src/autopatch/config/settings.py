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
    apply_patch: bool = False
    execute_tests: bool = False
    create_branch: bool = False
    create_commit: bool = False
    push_branch: bool = False
    create_pull_request: bool = False
    deploy: bool = False
    max_patch_attempts: int = Field(default=3, ge=1, le=10)
    require_clean_git_tree: bool = True


class ScannerConfig(BaseModel):
    name: str
    enabled: bool | Literal["auto"] = True
    required: bool = False
    timeout_seconds: int = Field(default=180, ge=1)
    config: str | None = None


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
    require_build_pass: bool = True
    require_regression_not_failed: bool = True
    require_security_rescan_pass: bool = True
    require_exploit_not_failed: bool = True


class PatchingSettings(BaseModel):
    supported_cwes: list[str] = Field(default_factory=lambda: ["CWE-89"])
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
    timeout_seconds: int = Field(default=30, ge=1)

    @model_validator(mode="after")
    def enabled_requires_repository(self) -> "GitHubAppSettings":
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


class PublishingSettings(BaseModel):
    branch_prefix: str = "fix/security"
    draft_pull_request: bool = True
    push_remote: str = "origin"
    github_app: GitHubAppSettings = Field(default_factory=GitHubAppSettings)


class DastSettings(BaseModel):
    enabled: bool = False
    authorized_targets: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def enabled_requires_authorized_target(self) -> "DastSettings":
        if self.enabled and not self.authorized_targets:
            raise ValueError("DAST requires at least one explicitly authorized target")
        for target in self.authorized_targets:
            parsed = urlsplit(target)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError(f"unsupported DAST target: {target}")
        return self


class DeploymentSettings(BaseModel):
    enabled: bool = False
    staging_command: list[str] = Field(default_factory=list)
    canary_command: list[str] = Field(default_factory=list)
    rollback_command: list[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=300, ge=1)
    rollback_runbook: str = "runbooks/rollback.md"

    @model_validator(mode="after")
    def enabled_requires_all_phases(self) -> "DeploymentSettings":
        if self.enabled and not all(
            (self.staging_command, self.canary_command, self.rollback_command)
        ):
            raise ValueError("deployment requires staging, canary, and rollback commands")
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
    def deploy_requires_pr(self) -> "HarnessSettings":
        if self.autonomy.deploy and not self.autonomy.create_pull_request:
            raise ValueError("deploy autonomy requires create_pull_request autonomy")
        if self.autonomy.create_commit and not self.autonomy.create_branch:
            raise ValueError("create_commit autonomy requires create_branch autonomy")
        if self.autonomy.push_branch and not self.autonomy.create_commit:
            raise ValueError("push_branch autonomy requires create_commit autonomy")
        if self.autonomy.create_pull_request and not self.autonomy.push_branch:
            raise ValueError("create_pull_request autonomy requires push_branch autonomy")
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
