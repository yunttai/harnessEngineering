from pydantic import BaseModel


class HttpLogRecord(BaseModel):
    timestamp: str
    method: str
    path: str
    source_ip: str
    status_code: int
