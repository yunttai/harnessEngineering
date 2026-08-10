import re


SQL_INJECTION_PATTERNS = (
    re.compile(r"(?i)'\s*or\s+['\d]"),
    re.compile(r"(?i)union\s+select"),
    re.compile(r"(?i)(--|/\*)"),
    re.compile(r"(?i)(sleep|benchmark)\s*\("),
)


def detect_sql_injection(value: str) -> list[str]:
    """Return matched rule expressions without executing the input."""
    return [pattern.pattern for pattern in SQL_INJECTION_PATTERNS if pattern.search(value)]
