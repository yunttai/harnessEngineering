from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class EventStatus(StrEnum):
    DETECTED = "DETECTED"
    CODE_LOCATED = "CODE_LOCATED"
    PATCH_GENERATED = "PATCH_GENERATED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    TEST_PASSED = "TEST_PASSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class AttackEvent(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    source_ip: str
    method: str
    path: str
    sanitized_payload: str
    attack_type: str = "SQL_INJECTION"
    severity: str = "HIGH"
    status: EventStatus = EventStatus.DETECTED
