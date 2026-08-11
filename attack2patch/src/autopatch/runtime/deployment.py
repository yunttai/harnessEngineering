from __future__ import annotations

from pathlib import Path

from autopatch.config import DeploymentSettings
from autopatch.runtime.command import CommandRunner
from autopatch.types import DeploymentPhase, DeploymentResult, StageStatus


class CommandDeploymentProvider:
    """Explicit argv-based staging/canary/observation/promotion/rollback provider."""

    name = "command-deployment"

    def __init__(
        self,
        settings: DeploymentSettings,
        *,
        repository_root: Path,
        runner: CommandRunner | None = None,
    ) -> None:
        self.settings = settings
        self.repository_root = repository_root.resolve()
        self.runner = runner or CommandRunner()

    def execute(self, target: Path, phase: DeploymentPhase) -> DeploymentResult:
        if not self.settings.enabled:
            raise PermissionError("deployment provider is disabled")
        runbook = (self.repository_root / self.settings.rollback_runbook).resolve()
        runbook.relative_to(self.repository_root)
        if not runbook.is_file():
            raise FileNotFoundError(f"rollback runbook not found: {runbook}")
        command = {
            DeploymentPhase.STAGING: self.settings.staging_command,
            DeploymentPhase.CANARY: self.settings.canary_command,
            DeploymentPhase.OBSERVATION: self.settings.observation_command,
            DeploymentPhase.PROMOTION: self.settings.promotion_command,
            DeploymentPhase.ROLLBACK: self.settings.rollback_command,
        }[phase]
        if not command:
            raise ValueError(f"no command configured for deployment phase {phase.value}")
        result = self.runner.run(
            list(command),
            cwd=target.resolve(),
            timeout_seconds=self.settings.timeout_seconds,
        )
        if result.timed_out:
            status = StageStatus.ERROR
            reason = "deployment command timed out"
        elif result.exit_code == 0:
            status = StageStatus.PASS
            reason = None
        else:
            status = StageStatus.FAIL
            reason = f"deployment command exited {result.exit_code}"
        return DeploymentResult(
            phase=phase,
            status=status,
            command=result.argv,
            exit_code=result.exit_code,
            duration_ms=result.duration_ms,
            stdout_excerpt=result.stdout,
            stderr_excerpt=result.stderr,
            reason=reason,
        )
