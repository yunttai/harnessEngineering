from pydantic import BaseModel


class PatchCandidate(BaseModel):
    finding_id: str
    diff: str
    status: str = "GENERATED"
