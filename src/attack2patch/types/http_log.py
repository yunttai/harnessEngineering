import json
import re
from datetime import datetime
from ipaddress import ip_address

from pydantic import Field, field_validator

from attack2patch.types.attack_event import HttpMethod
from attack2patch.types.base import StrictModel


SENSITIVE_KEYS = re.compile(
    r"(?i)(authorization|cookie|token|password|passwd|secret|api[_-]?key)"
)
REDACTED = "***REDACTED***"


class HttpLogRecord(StrictModel):
    timestamp: datetime
    method: HttpMethod
    path: str
    parameters: dict[str, str] = Field(default_factory=dict)
    source_ip: str
    status_code: int = Field(ge=100, le=599)
    headers: dict[str, str] = Field(default_factory=dict)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value.startswith("/") or ".." in value.split("/"):
            raise ValueError("invalid HTTP path")
        return value

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str) -> str:
        ip_address(value)
        return value

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value

    def sanitized_parameters(self) -> dict[str, str]:
        return {
            key: REDACTED if SENSITIVE_KEYS.search(key) else value
            for key, value in self.parameters.items()
        }

    def sanitized_headers(self) -> dict[str, str]:
        return {
            key: REDACTED if SENSITIVE_KEYS.search(key) else value
            for key, value in self.headers.items()
        }

    def detection_values(self) -> list[str]:
        # Inspect raw values in memory, then persist only the sanitized representation.
        return list(self.parameters.values())

    def sanitized_payload(self) -> str:
        return json.dumps(self.sanitized_parameters(), ensure_ascii=False, sort_keys=True)
