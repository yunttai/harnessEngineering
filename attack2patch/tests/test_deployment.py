from __future__ import annotations

from pathlib import Path

from autopatch.config import HarnessSettings
from autopatch.service.deployment import DeploymentService
from autopatch.types import (
    DeploymentPhase,
    DeploymentResult,
    PublishingResult,
    PullRequestResult,
    RunReport,
    RunState,
    StageStatus,
)


class _DeploymentProvider:
    name = "fake-deployment"

    def __init__(
        self,
        statuses: dict[DeploymentPhase, StageStatus],
        observations: list[StageStatus] | None = None,
    ) -> None:
        self.statuses = statuses
        self.observations = list(observations or [])
        self.phases: list[DeploymentPhase] = []

    def execute(self, target: Path, phase: DeploymentPhase) -> DeploymentResult:
        self.phases.append(phase)
        if phase is DeploymentPhase.OBSERVATION and self.observations:
            status = self.observations.pop(0)
        else:
            status = self.statuses.get(phase, StageStatus.PASS)
        return DeploymentResult(
            phase=phase,
            status=status,
            command=["deploy", phase.value.lower()],
            exit_code=0 if status is StageStatus.PASS else 1,
            reason=None if status is StageStatus.PASS else "failed",
        )


def _settings() -> HarnessSettings:
    return HarnessSettings.model_validate(
        {
            "autonomy": {
                "apply_patch": True,
                "create_branch": True,
                "create_commit": True,
                "push_branch": True,
                "create_pull_request": True,
                "deploy": True,
            },
            "deployment": {
                "enabled": True,
                "staging_command": ["deploy", "staging"],
                "canary_command": ["deploy", "canary"],
                "observation_command": ["observe", "canary"],
                "promotion_command": ["deploy", "production"],
                "rollback_command": ["deploy", "rollback"],
                "observation_window_seconds": 2,
                "observation_interval_seconds": 1,
                "minimum_observation_passes": 2,
                "max_observation_attempts": 3,
            },
        }
    )


def _report(tmp_path: Path) -> RunReport:
    return RunReport(
        run_id="run-deploy",
        target=str(tmp_path),
        config_path="config/harness.yaml",
        state=RunState.PR_CREATED,
        publishing=PublishingResult(
            base_sha="base-sha",
            branch="Attack2patch",
            remote="origin",
            commit_sha="commit-sha",
            pushed=True,
        ),
        pull_request=PullRequestResult(
            number=1,
            url="https://example.test/pr/1",
            state="open",
            draft=True,
            head="security/fix",
            base="main",
        ),
    )


def test_deployment_promotes_staging_then_canary(tmp_path: Path) -> None:
    provider = _DeploymentProvider({})
    now = [0.0]
    report = DeploymentService(
        settings=_settings(),
        provider=provider,
        monotonic=lambda: now[0],
        sleeper=lambda seconds: now.__setitem__(0, now[0] + seconds),
    ).deploy(
        tmp_path,
        _report(tmp_path),
        approved=True,
    )

    assert report.state is RunState.DEPLOYED
    assert provider.phases == [
        DeploymentPhase.STAGING,
        DeploymentPhase.CANARY,
        DeploymentPhase.OBSERVATION,
        DeploymentPhase.OBSERVATION,
        DeploymentPhase.OBSERVATION,
        DeploymentPhase.PROMOTION,
    ]
    observations = [
        result for result in report.deployments if result.phase is DeploymentPhase.OBSERVATION
    ]
    assert [result.attempt for result in observations] == [1, 2, 3]


def test_canary_failure_triggers_rollback_and_preserves_evidence(tmp_path: Path) -> None:
    provider = _DeploymentProvider({DeploymentPhase.CANARY: StageStatus.FAIL})
    report = DeploymentService(settings=_settings(), provider=provider).deploy(
        tmp_path,
        _report(tmp_path),
        approved=True,
    )

    assert report.state is RunState.DEPLOY_FAILED
    assert provider.phases == [
        DeploymentPhase.STAGING,
        DeploymentPhase.CANARY,
        DeploymentPhase.ROLLBACK,
    ]
    assert [item.status for item in report.deployments] == [
        StageStatus.PASS,
        StageStatus.FAIL,
        StageStatus.PASS,
    ]


def test_observation_failure_triggers_rollback(tmp_path: Path) -> None:
    provider = _DeploymentProvider(
        {},
        observations=[StageStatus.PASS, StageStatus.FAIL],
    )
    now = [0.0]
    report = DeploymentService(
        settings=_settings(),
        provider=provider,
        monotonic=lambda: now[0],
        sleeper=lambda seconds: now.__setitem__(0, now[0] + seconds),
    ).deploy(tmp_path, _report(tmp_path), approved=True)

    assert report.state is RunState.DEPLOY_FAILED
    assert provider.phases[-3:] == [
        DeploymentPhase.OBSERVATION,
        DeploymentPhase.OBSERVATION,
        DeploymentPhase.ROLLBACK,
    ]
    assert report.events[-1].metadata["failed_phase"] == "OBSERVATION"
    assert report.events[-1].metadata["failed_attempt"] == 2


def test_observation_attempt_exhaustion_fails_closed_and_rolls_back(tmp_path: Path) -> None:
    provider = _DeploymentProvider({})
    report = DeploymentService(
        settings=_settings(),
        provider=provider,
        monotonic=lambda: 0.0,
        sleeper=lambda _seconds: None,
    ).deploy(tmp_path, _report(tmp_path), approved=True)

    assert report.state is RunState.DEPLOY_FAILED
    assert provider.phases[-1] is DeploymentPhase.ROLLBACK
    assert "attempt bound" in (report.deployments[-2].reason or "")
    assert report.events[-1].metadata["failed_attempt"] == 3


def test_promotion_failure_triggers_rollback(tmp_path: Path) -> None:
    provider = _DeploymentProvider({DeploymentPhase.PROMOTION: StageStatus.FAIL})
    now = [0.0]
    report = DeploymentService(
        settings=_settings(),
        provider=provider,
        monotonic=lambda: now[0],
        sleeper=lambda seconds: now.__setitem__(0, now[0] + seconds),
    ).deploy(tmp_path, _report(tmp_path), approved=True)

    assert report.state is RunState.DEPLOY_FAILED
    assert provider.phases[-2:] == [
        DeploymentPhase.PROMOTION,
        DeploymentPhase.ROLLBACK,
    ]
    assert report.events[-1].metadata["failed_phase"] == "PROMOTION"
