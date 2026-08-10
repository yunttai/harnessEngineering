from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import Field, field_validator


from attack2patch.types.base import StrictModel


class PatchStatus(StrEnum):
    GENERATED = "GENERATED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    VALIDATED = "VALIDATED"
    VALIDATION_FAILED = "VALIDATION_FAILED"


class PatchCandidate(StrictModel):
    id: UUID = Field(default_factory=uuid4)
    finding_id: UUID
    file_path: str
    diff: str
    reason: str
    before_sha256: str
    status: PatchStatus = PatchStatus.GENERATED
    workspace_path: str | None = None
    validation_result: dict[str, Any] | None = None
    validated_sha256: str | None = None

    @field_validator("file_path")
    @classmethod
    def validate_relative_file_path(cls, value: str) -> str:
        normalized = value.replace("\\", "/")
        if normalized.startswith("/") or ".." in normalized.split("/"):
            raise ValueError("file_path must stay within the repository")
        return normalized
