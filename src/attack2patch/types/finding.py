from uuid import UUID, uuid4

from pydantic import Field, PositiveInt, field_validator


from attack2patch.types.base import StrictModel


class CodeFinding(StrictModel):
    id: UUID = Field(default_factory=uuid4)
    event_id: UUID
    file_path: str
    function_name: str
    line_number: PositiveInt
    rule_id: str
    vulnerable_code: str

    @field_validator("file_path")
    @classmethod
    def validate_relative_file_path(cls, value: str) -> str:
        normalized = value.replace("\\", "/")
        if normalized.startswith("/") or ".." in normalized.split("/"):
            raise ValueError("file_path must stay within the repository")
        return normalized
