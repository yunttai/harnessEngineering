from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import Field


from attack2patch.types.base import StrictModel


class DeploymentStatus(StrEnum):
    BUILDING = "BUILDING"
    DEPLOYING = "DEPLOYING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


class Deployment(StrictModel):
    id: UUID = Field(default_factory=uuid4)
    patch_id: UUID
    previous_image: str
    candidate_image: str
    status: DeploymentStatus = DeploymentStatus.BUILDING
    build_log: str = ""
    healthcheck_result: dict[str, Any] | None = None
    deployed_at: datetime | None = None
    error: str | None = None
