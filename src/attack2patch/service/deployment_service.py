from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol
from uuid import UUID

from attack2patch.config.settings import Settings
from attack2patch.repo.sqlite_repository import SQLiteRepository
from attack2patch.service.workspace_integrity import workspace_digest
from attack2patch.types.attack_event import EventStatus
from attack2patch.types.deployment import Deployment, DeploymentStatus
from attack2patch.types.patch import PatchStatus
from attack2patch.types.runtime_result import BuildResult, DeploymentVerification


class ImageBuilder(Protocol):
    def build(self, build_context: Path, image: str) -> BuildResult: ...


class Deployer(Protocol):
    def deploy(self, image: str) -> str: ...

    def rollback(self, image: str) -> str: ...


class Verifier(Protocol):
    def verify(self) -> DeploymentVerification: ...


class DeploymentService:
    def __init__(
        self,
        settings: Settings,
        repository: SQLiteRepository,
        builder: ImageBuilder,
        deployer: Deployer,
        verifier: Verifier,
    ) -> None:
        self.settings = settings
        self.repository = repository
        self.builder = builder
        self.deployer = deployer
        self.verifier = verifier

    def deploy_patch(self, patch_id: str | UUID, *, approved: bool) -> Deployment:
        if self.settings.deploy_approval_required and not approved:
            raise PermissionError("explicit deployment approval is required")
        patch = self.repository.get_patch(patch_id)
        if not patch:
            raise LookupError("patch candidate not found")
        if patch.status != PatchStatus.VALIDATED or not patch.workspace_path:
            raise RuntimeError("only a fully validated patch can be deployed")

        previous = self.repository.latest_completed_deployment()
        previous_image = previous.candidate_image if previous else self.settings.baseline_image
        candidate_image = f"attack2patch-demo:{str(patch.id).replace('-', '')[:12]}"
        deployment = Deployment(
            patch_id=patch.id,
            previous_image=previous_image,
            candidate_image=candidate_image,
        )
        self.repository.save_deployment(deployment)

        deployed = False
        try:
            workspace = Path(patch.workspace_path)
            if not patch.validated_sha256:
                raise RuntimeError("validated workspace digest is missing")
            if workspace_digest(workspace) != patch.validated_sha256:
                raise RuntimeError("validated workspace changed before image build")
            build_context = workspace / self.settings.demo_app_path
            build = self.builder.build(build_context, candidate_image)
            deployment.build_log = build.log
            deployment.status = DeploymentStatus.DEPLOYING
            self.repository.save_deployment(deployment)
            deployed = True
            self.deployer.deploy(candidate_image)
            verification = self.verifier.verify()
            deployment.healthcheck_result = verification.as_dict()
            if not verification.passed:
                raise RuntimeError("post-deployment health, regression, or attack check failed")
            deployment.status = DeploymentStatus.COMPLETED
            deployment.deployed_at = datetime.now(timezone.utc)
            self.repository.save_deployment(deployment)
            self._set_event_status(patch.id, EventStatus.COMPLETED)
            return deployment
        except Exception as exc:  # Deployment is fail-closed and always attempts recovery.
            deployment.error = f"{type(exc).__name__}: {exc}"
            if deployed:
                self._automatic_rollback(deployment)
            else:
                deployment.status = DeploymentStatus.FAILED
                self.repository.save_deployment(deployment)
            self._set_event_status(patch.id, EventStatus.FAILED, deployment.error)
            return deployment

    def manual_rollback(self, deployment_id: str | UUID, *, approved: bool) -> Deployment:
        if not approved:
            raise PermissionError("explicit rollback approval is required")
        deployment = self.repository.get_deployment(deployment_id)
        if not deployment:
            raise LookupError("deployment not found")
        if deployment.status != DeploymentStatus.COMPLETED:
            raise RuntimeError("only a completed deployment can be manually rolled back")
        self._automatic_rollback(deployment)
        return deployment

    def _automatic_rollback(self, deployment: Deployment) -> None:
        candidate_result = deployment.healthcheck_result
        try:
            self.deployer.rollback(deployment.previous_image)
            verification = self.verifier.verify()
            deployment.healthcheck_result = {
                "candidate": candidate_result,
                "rollback": verification.as_dict(),
            }
            if not verification.health_ok:
                raise RuntimeError("previous image failed rollback healthcheck")
            deployment.status = DeploymentStatus.ROLLED_BACK
        except Exception as rollback_error:
            deployment.status = DeploymentStatus.FAILED
            deployment.error = (
                f"{deployment.error or ''}; rollback failed: "
                f"{type(rollback_error).__name__}: {rollback_error}"
            ).strip("; ")
        self.repository.save_deployment(deployment)

    def _set_event_status(
        self, patch_id: UUID, status: EventStatus, error: str | None = None
    ) -> None:
        patch = self.repository.get_patch(patch_id)
        finding = self.repository.get_finding(patch.finding_id) if patch else None
        event = self.repository.get(finding.event_id) if finding else None
        if event:
            event.status = status
            event.error = error
            self.repository.save_event(event)
