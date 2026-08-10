from pydantic import BaseModel


class CodeFinding(BaseModel):
    file_path: str
    function_name: str
    line_number: int
    rule_id: str
    vulnerable_code: str
