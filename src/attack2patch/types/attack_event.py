from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import Field, field_validator

from attack2patch.types.base import StrictModel


class HttpMethod(StrEnum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class AttackType(StrEnum):
    SQL_INJECTION = "SQL_INJECTION"


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventStatus(StrEnum):
    DETECTED = "DETECTED"
    CODE_LOCATED = "CODE_LOCATED"
    PATCH_GENERATED = "PATCH_GENERATED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    TEST_PASSED = "TEST_PASSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class AttackEvent(StrictModel):
    id: UUID = Field(default_factory=uuid4)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: str
    method: HttpMethod
    path: str
    sanitized_payload: str
    attack_type: AttackType = AttackType.SQL_INJECTION
    severity: Severity = Severity.HIGH
    status: EventStatus = EventStatus.DETECTED
    evidence: dict[str, Any]
    error: str | None = None

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value.startswith("/") or ".." in value.split("/"):
            raise ValueError("path must be an absolute HTTP path without traversal")
        return value
