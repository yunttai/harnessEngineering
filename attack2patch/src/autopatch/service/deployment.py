from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

from autopatch.config import HarnessSettings
from autopatch.providers import DeploymentProvider
from autopatch.types import DeploymentPhase, DeploymentResult, RunReport, RunState, StageStatus


class DeploymentService:
    """Promote a pushed commit through staging, canary, observation, and production."""

    def __init__(
        self,
        *,
        settings: HarnessSettings,
        provider: DeploymentProvider,
        monotonic: Callable[[], float] | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self.settings = settings
        self.provider = provider
        self.monotonic = monotonic or time.monotonic
        self.sleeper = sleeper or time.sleep

    def deploy(self, target: Path, report: RunReport, *, approved: bool) -> RunReport:
        if not approved:
            raise PermissionError("deployment requires explicit CLI approval")
        if not self.settings.autonomy.deploy or not self.settings.deployment.enabled:
            raise PermissionError("deployment policy gates are disabled")
        publishing = report.publishing
        if report.state not in {RunState.APPLIED, RunState.PR_CREATED}:
            raise ValueError("deployment requires a published Attack2Patch run")
        if (
            publishing is None
            or not publishing.pushed
            or not publishing.commit_sha
            or not publishing.branch
            or not publishing.remote
        ):
            raise ValueError("deployment requires pushed commit, branch, and remote evidence")

        target = target.resolve()
        for phase in (DeploymentPhase.STAGING, DeploymentPhase.CANARY):
            result = self.provider.execute(target, phase)
            report.deployments.append(result)
            if result.status is not StageStatus.PASS:
                self._fail_and_rollback(report, target, phase, result)
                return report

        if not self._observe(target, report):
            return report

        promotion = self.provider.execute(target, DeploymentPhase.PROMOTION)
        report.deployments.append(promotion)
        if promotion.status is not StageStatus.PASS:
            self._fail_and_rollback(
                report,
                target,
                DeploymentPhase.PROMOTION,
                promotion,
            )
            return report

        report.transition(
            RunState.DEPLOYED,
            "staging, canary, bounded observation, and production promotion passed",
            commit_sha=publishing.commit_sha,
            branch=publishing.branch,
            remote=publishing.remote,
            observation_passes=sum(
                1
                for item in report.deployments
                if item.phase is DeploymentPhase.OBSERVATION
                and item.status is StageStatus.PASS
            ),
        )
        return report

    def _observe(self, target: Path, report: RunReport) -> bool:
        policy = self.settings.deployment
        started = self.monotonic()
        passes = 0
        for attempt in range(1, policy.max_observation_attempts + 1):
            result = self.provider.execute(target, DeploymentPhase.OBSERVATION)
            result.attempt = attempt
            report.deployments.append(result)
            if result.status is not StageStatus.PASS:
                self._fail_and_rollback(
                    report,
                    target,
                    DeploymentPhase.OBSERVATION,
                    result,
                )
                return False
            passes += 1
            elapsed = self.monotonic() - started
            if elapsed >= policy.observation_window_seconds and (
                passes >= policy.minimum_observation_passes
            ):
                return True
            remaining = policy.observation_window_seconds - elapsed
            if attempt < policy.max_observation_attempts:
                self.sleeper(min(float(policy.observation_interval_seconds), max(0.0, remaining)))

        exhausted = DeploymentResult(
            phase=DeploymentPhase.OBSERVATION,
            status=StageStatus.ERROR,
            command=[],
            attempt=policy.max_observation_attempts,
            reason=(
                "observation attempt bound was exhausted before the window and pass "
                "requirements were satisfied"
            ),
        )
        report.deployments.append(exhausted)
        self._fail_and_rollback(
            report,
            target,
            DeploymentPhase.OBSERVATION,
            exhausted,
        )
        return False

    def _fail_and_rollback(
        self,
        report: RunReport,
        target: Path,
        failed_phase: DeploymentPhase,
        failed: DeploymentResult,
    ) -> None:
        rollback = self._rollback(target, failed_phase, failed)
        report.deployments.append(rollback)
        report.transition(
            RunState.DEPLOY_FAILED,
            f"{failed_phase.value.lower()} deployment failed; rollback attempted",
            failed_phase=failed_phase.value,
            failed_attempt=failed.attempt,
            rollback_status=rollback.status.value,
        )

    def _rollback(
        self,
        target: Path,
        failed_phase: DeploymentPhase,
        failed: DeploymentResult,
    ) -> DeploymentResult:
        try:
            return self.provider.execute(target, DeploymentPhase.ROLLBACK)
        except Exception as exc:
            return DeploymentResult(
                phase=DeploymentPhase.ROLLBACK,
                status=StageStatus.ERROR,
                command=[],
                reason=(
                    f"rollback after {failed_phase.value} failed: "
                    f"{type(exc).__name__}: {exc}; original={failed.reason or failed.status.value}"
                ),
            )
