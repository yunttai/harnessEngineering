import json
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from attack2patch.config.settings import Settings
from attack2patch.repo.sqlite_repository import SQLiteRepository
from attack2patch.runtime.candidate_validator import validate_workspace
from attack2patch.runtime.compose_deployer import ComposeDeployer
from attack2patch.runtime.health_checker import PostDeploymentVerifier
from attack2patch.runtime.image_builder import DockerImageBuilder
from attack2patch.service.attack_workflow import AttackWorkflowService
from attack2patch.service.deployment_service import DeploymentService
from attack2patch.types.deployment import DeploymentStatus
from attack2patch.types.http_log import HttpLogRecord
from attack2patch.types.runtime_result import DeploymentVerification


class ForceFirstCandidateFailure:
    """Use real probes, but force the first candidate verdict to fail for rollback QA."""

    def __init__(self, real_verifier: PostDeploymentVerifier) -> None:
        self.real_verifier = real_verifier
        self.calls = 0

    def verify(self) -> DeploymentVerification:
        self.calls += 1
        result = self.real_verifier.verify()
        if self.calls != 1:
            return result
        details = dict(result.details)
        details["forced_failure"] = "rollback rehearsal"
        return DeploymentVerification(
            health_ok=result.health_ok,
            normal_request_ok=result.normal_request_ok,
            attack_test_ok=False,
            details=details,
        )


def main() -> int:
    repository_root = Path(__file__).parents[1].resolve()
    with tempfile.TemporaryDirectory(
        prefix="attack2patch-rollback-", ignore_cleanup_errors=True
    ) as temporary:
        temporary_root = Path(temporary)
        settings = Settings(
            database_url=f"sqlite:///{temporary_root / 'rollback.db'}",
            workspace=temporary_root / "work",
            repository_root=repository_root,
            compose_file=repository_root / "docker-compose.yml",
            demo_base_url="http://127.0.0.1:5000",
            compose_project_name="attack2patch",
        )
        repository = SQLiteRepository(settings.database_url)
        workflow = AttackWorkflowService(settings, repository, validate_workspace)
        event = workflow.analyze(
            HttpLogRecord(
                timestamp=datetime.now(timezone.utc),
                method="GET",
                path="/api/users",
                parameters={"name": "' OR 1=1--"},
                source_ip="127.0.0.1",
                status_code=200,
            )
        )
        if not event:
            raise RuntimeError("rollback rehearsal attack was not detected")
        patch = workflow.generate_patch(event.id)
        patch = workflow.approve_patch(patch.id)
        patch, validation = workflow.validate_patch(patch.id)
        if not validation.deployable:
            raise RuntimeError("rollback rehearsal candidate did not validate")

        verifier = ForceFirstCandidateFailure(
            PostDeploymentVerifier(settings.demo_base_url)
        )
        deployment_service = DeploymentService(
            settings,
            repository,
            builder=DockerImageBuilder(),
            deployer=ComposeDeployer(
                settings.resolved_compose_file, settings.compose_project_name
            ),
            verifier=verifier,
        )
        started = time.monotonic()
        deployment = deployment_service.deploy_patch(patch.id, approved=True)
        elapsed = time.monotonic() - started
        evidence = {
            "deployment_id": str(deployment.id),
            "status": deployment.status.value,
            "candidate_image": deployment.candidate_image,
            "previous_image": deployment.previous_image,
            "elapsed_seconds": round(elapsed, 3),
            "candidate_health": deployment.healthcheck_result["candidate"]["health_ok"],
            "rollback_health": deployment.healthcheck_result["rollback"]["health_ok"],
        }
        print(json.dumps(evidence, sort_keys=True))
        repository.close()
        if deployment.status != DeploymentStatus.ROLLED_BACK:
            raise RuntimeError("automatic rollback did not complete")
        if not evidence["rollback_health"] or elapsed >= 60:
            raise RuntimeError("rollback health or time objective failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
