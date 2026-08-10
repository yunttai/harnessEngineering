import re
from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    expression: re.Pattern[str]


@dataclass(frozen=True)
class DetectionMatch:
    rule_id: str
    matched_text: str


SQL_INJECTION_RULES = (
    DetectionRule(
        "sqli-boolean-bypass",
        re.compile(r"(?i)'\s*or\s+(?:'[^']*'|\d+|\w+)\s*="),
    ),
    DetectionRule("sqli-union-select", re.compile(r"(?i)\bunion\s+(?:all\s+)?select\b")),
    DetectionRule("sqli-comment", re.compile(r"(?i)(--|/\*)")),
    DetectionRule("sqli-time-delay", re.compile(r"(?i)\b(sleep|benchmark)\s*\(")),
    DetectionRule("sqli-stacked-query", re.compile(r"(?i);\s*(select|insert|update|delete)\b")),
)


def detect_sql_injection(value: str) -> list[str]:
    """Return stable rule IDs without executing or normalizing the attack input."""
    return [rule.rule_id for rule in SQL_INJECTION_RULES if rule.expression.search(value)]


def inspect_sql_injection(value: str) -> list[DetectionMatch]:
    matches: list[DetectionMatch] = []
    for rule in SQL_INJECTION_RULES:
        match = rule.expression.search(value)
        if match:
            matches.append(DetectionMatch(rule.rule_id, match.group(0)))
    return matches
