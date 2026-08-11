from __future__ import annotations

from pathlib import Path

import pytest

from autopatch.service.detection import DetectionService
from autopatch.service.normalization import normalize_relative_path
from autopatch.types import Finding, Severity


def test_normalize_relative_path_accepts_dot_prefix() -> None:
    assert normalize_relative_path("./src/app.py") == "src/app.py"
    assert normalize_relative_path("src\\app.py") == "src/app.py"


@pytest.mark.parametrize(
    "value",
    ["../secret", "./../secret", "../../secret", "/etc/passwd", "", "."],
)
def test_normalize_relative_path_rejects_traversal(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_relative_path(value)


class _Scanner:
    required = True

    def __init__(self, name: str, finding: Finding) -> None:
        self.name = name
        self.finding = finding

    def available(self) -> bool:
        return True

    def scan(self, target):
        return [self.finding]


def test_cross_scanner_same_location_is_correlated() -> None:
    first = Finding(
        finding_id="VULN-FIRST",
        fingerprint="a" * 64,
        type="SQL injection",
        cwe="CWE-89",
        severity=Severity.HIGH,
        file="app.py",
        line=10,
        scanner="scanner-a",
        message="first",
    )
    second = first.model_copy(
        update={
            "finding_id": "VULN-SECOND",
            "fingerprint": "b" * 64,
            "scanner": "scanner-b",
            "message": "second",
        }
    )

    result = DetectionService(
        [_Scanner("scanner-a", first), _Scanner("scanner-b", second)]
    ).scan(Path("."))

    assert len(result.findings) == 1
    assert result.findings[0].metadata["corroborating_scanners"] == [
        "scanner-a",
        "scanner-b",
    ]
