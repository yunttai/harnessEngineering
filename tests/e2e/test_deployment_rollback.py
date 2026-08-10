from dataclasses import dataclass, field

from attack2patch.runtime.health_checker import DeploymentVerification
from attack2patch.runtime.image_builder import BuildResult
from attack2patch.service.deployment_service import DeploymentService
from attack2patch.types.deployment import DeploymentStatus


@dataclass
class FakeBuilder:
    images: list[str] = field(default_factory=list)

    def build(self, build_context, image):
        assert build_context.name == "demo-app"
        self.images.append(image)
        return BuildResult(image=image, log="fake build succeeded")


class FailingBuilder:
    def build(self, build_context, image):
        raise RuntimeError("simulated build failure")


@dataclass
class FakeDeployer:
    deployed: list[str] = field(default_factory=list)
    rolled_back: list[str] = field(default_factory=list)

    def deploy(self, image):
        self.deployed.append(image)
        return "deployed"

    def rollback(self, image):
        self.rolled_back.append(image)
        return "rolled back"


@dataclass
class SequenceVerifier:
    results: list[DeploymentVerification]

    def verify(self):
        return self.results.pop(0)


def verification(*, health=True, normal=True, attack=True):
    return DeploymentVerification(health, normal, attack, {"fake": True})


def validated_patch(workflow_bundle):
    event = workflow_bundle.workflow.analyze(workflow_bundle.attack_record())
    patch = workflow_bundle.workflow.generate_patch(event.id)
    patch = workflow_bundle.workflow.approve_patch(patch.id)
    patch, result = workflow_bundle.workflow.validate_patch(patch.id)
    assert result.deployable
    return patch


def test_successful_deployment_records_candidate(workflow_bundle):
    patch = validated_patch(workflow_bundle)
    builder = FakeBuilder()
    deployer = FakeDeployer()
    service = DeploymentService(
        workflow_bundle.settings,
        workflow_bundle.repository,
        builder=builder,
        deployer=deployer,
        verifier=SequenceVerifier([verification()]),
    )
    deployment = service.deploy_patch(patch.id, approved=True)
    assert deployment.status == DeploymentStatus.COMPLETED
    assert builder.images == [deployment.candidate_image]
    assert deployer.deployed == [deployment.candidate_image]
    assert deployer.rolled_back == []


def test_failed_deployment_rolls_back(workflow_bundle):
    patch = validated_patch(workflow_bundle)
    deployer = FakeDeployer()
    service = DeploymentService(
        workflow_bundle.settings,
        workflow_bundle.repository,
        builder=FakeBuilder(),
        deployer=deployer,
        verifier=SequenceVerifier(
            [verification(attack=False), verification(health=True, normal=True, attack=False)]
        ),
    )
    deployment = service.deploy_patch(patch.id, approved=True)
    assert deployment.status == DeploymentStatus.ROLLED_BACK
    assert deployer.deployed == [deployment.candidate_image]
    assert deployer.rolled_back == [deployment.previous_image]
    assert deployment.healthcheck_result["candidate"]["attack_test_ok"] is False
    assert deployment.healthcheck_result["rollback"]["health_ok"] is True


def test_deployment_requires_explicit_approval(workflow_bundle):
    patch = validated_patch(workflow_bundle)
    service = DeploymentService(
        workflow_bundle.settings,
        workflow_bundle.repository,
        builder=FakeBuilder(),
        deployer=FakeDeployer(),
        verifier=SequenceVerifier([verification()]),
    )
    try:
        service.deploy_patch(patch.id, approved=False)
    except PermissionError:
        pass
    else:
        raise AssertionError("deployment without explicit approval must fail")


def test_build_failure_does_not_touch_running_service(workflow_bundle):
    patch = validated_patch(workflow_bundle)
    deployer = FakeDeployer()
    service = DeploymentService(
        workflow_bundle.settings,
        workflow_bundle.repository,
        builder=FailingBuilder(),
        deployer=deployer,
        verifier=SequenceVerifier([verification()]),
    )
    deployment = service.deploy_patch(patch.id, approved=True)
    assert deployment.status == DeploymentStatus.FAILED
    assert deployer.deployed == []
    assert deployer.rolled_back == []


def test_manual_rollback_restores_previous_image(workflow_bundle):
    patch = validated_patch(workflow_bundle)
    deployer = FakeDeployer()
    service = DeploymentService(
        workflow_bundle.settings,
        workflow_bundle.repository,
        builder=FakeBuilder(),
        deployer=deployer,
        verifier=SequenceVerifier([verification(), verification()]),
    )
    deployment = service.deploy_patch(patch.id, approved=True)
    deployment = service.manual_rollback(deployment.id, approved=True)
    assert deployment.status == DeploymentStatus.ROLLED_BACK
    assert deployer.rolled_back == [workflow_bundle.settings.baseline_image]


def test_post_validation_workspace_change_blocks_build(workflow_bundle):
    patch = validated_patch(workflow_bundle)
    candidate = workflow_bundle.settings.resolved_workspace / str(patch.id) / patch.file_path
    candidate.write_text(candidate.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")
    builder = FakeBuilder()
    deployer = FakeDeployer()
    service = DeploymentService(
        workflow_bundle.settings,
        workflow_bundle.repository,
        builder=builder,
        deployer=deployer,
        verifier=SequenceVerifier([verification()]),
    )
    deployment = service.deploy_patch(patch.id, approved=True)
    assert deployment.status == DeploymentStatus.FAILED
    assert "workspace changed" in deployment.error
    assert builder.images == []
    assert deployer.deployed == []
