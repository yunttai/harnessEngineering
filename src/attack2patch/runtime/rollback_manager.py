from attack2patch.runtime.compose_deployer import ComposeDeployer
from attack2patch.runtime.health_checker import DeploymentVerification, PostDeploymentVerifier


class RollbackManager:
    """Restore an immutable known-good tag and verify it before reporting success."""

    def __init__(self, deployer: ComposeDeployer, verifier: PostDeploymentVerifier) -> None:
        self.deployer = deployer
        self.verifier = verifier

    def rollback(self, previous_image: str) -> DeploymentVerification:
        self.deployer.rollback(previous_image)
        return self.verifier.verify()
