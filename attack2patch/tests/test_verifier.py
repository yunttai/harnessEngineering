from __future__ import annotations

from pathlib import Path

from autopatch.config.settings import VerificationSettings
from autopatch.runtime.builtin_patcher import BuiltinCwe89Patcher
from autopatch.runtime.builtin_scanner import BuiltinPythonScanner
from autopatch.runtime.verifier import LocalCopyVerifier
from autopatch.service.analysis import RuleBasedAnalyzer
from autopatch.service.detection import DetectionService
from autopatch.types import StageStatus


def test_verifier_builds_tests_rescans_and_checks_exploit(vulnerable_project: Path) -> None:
    scanner = BuiltinPythonScanner()
    detection = DetectionService([scanner])
    finding = next(item for item in scanner.scan(vulnerable_project) if item.cwe == "CWE-89")
    analysis = RuleBasedAnalyzer().analyze(vulnerable_project, finding)
    candidate = BuiltinCwe89Patcher().generate(vulnerable_project, finding, analysis)[0]
    verifier = LocalCopyVerifier(
        detection=detection,
        settings=VerificationSettings(
            execute_project_tests=True,
            execute_project_security_tests=True,
        ),
        excluded_directories={".git", ".autopatch", "__pycache__"},
    )

    evaluation = verifier.verify(vulnerable_project, finding, candidate)
    report = evaluation.verification
    assert report.eligible is True
    assert report.confidence == "full"
    assert report.build.status is StageStatus.PASS
    assert report.functional_test.status is StageStatus.PASS
    assert report.security_rescan.status is StageStatus.PASS
    assert report.exploit_test.status is StageStatus.PASS
    assert report.exploit_test.metadata["manifest_security_tests"][0]["id"] == "cwe-89-get-user"
    assert report.score.total == 100


class _UnavailableOriginalScanner:
    name = "builtin-python"
    required = False

    def available(self) -> bool:
        return False

    def scan(self, target: Path):  # pragma: no cover - must not be called
        raise AssertionError(target)


def test_rescan_fails_closed_when_original_scanner_did_not_execute(
    vulnerable_project: Path,
) -> None:
    finding = next(
        item for item in BuiltinPythonScanner().scan(vulnerable_project) if item.cwe == "CWE-89"
    )
    verifier = LocalCopyVerifier(
        detection=DetectionService([_UnavailableOriginalScanner()]),
        settings=VerificationSettings(),
        excluded_directories={".git", ".autopatch", "__pycache__"},
    )
    result = verifier._security_rescan(vulnerable_project, finding)
    assert result.status is StageStatus.ERROR
    assert "did not execute" in (result.reason or "")
