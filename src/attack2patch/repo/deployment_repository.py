from typing import Protocol

from attack2patch.types.deployment import Deployment


class DeploymentRepository(Protocol):
    def save(self, deployment: Deployment) -> None: ...
