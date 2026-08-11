from __future__ import annotations

from pathlib import Path

from autopatch.config.settings import VerificationSettings
from autopatch.runtime.builtin_patcher import BuiltinCwe89Patcher
from autopatch.runtime.builtin_scanner import BuiltinPythonScanner
from autopatch.runtime.builtin_security_patchers import (
    BuiltinCwe22FlaskPatcher,
    BuiltinCwe78Patcher,
    BuiltinCwe502YamlPatcher,
)
from autopatch.runtime.patch_apply import SafePatchApplier
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
            require_differential_exploit=True,
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
    assert report.exploit_baseline is not None
    assert report.exploit_baseline.status is StageStatus.PASS
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


def test_extended_deterministic_patchers_have_independent_ast_oracles(tmp_path: Path) -> None:
    cases = [
        (
            "CWE-78",
            BuiltinCwe78Patcher(),
            '''import subprocess
def run(host):
    return subprocess.run(f"ping -c 1 {host}", shell=True)
''',
        ),
        (
            "CWE-502",
            BuiltinCwe502YamlPatcher(),
            '''import yaml
def parse(payload):
    return yaml.load(payload, Loader=yaml.UnsafeLoader)
''',
        ),
        (
            "CWE-22",
            BuiltinCwe22FlaskPatcher(),
            '''import flask
import os
ROOT = "/srv/files"
def download(name):
    return flask.send_file(os.path.join(ROOT, name))
''',
        ),
    ]
    scanner = BuiltinPythonScanner()
    verifier = LocalCopyVerifier(
        detection=DetectionService([scanner]),
        settings=VerificationSettings(),
        excluded_directories={".git", ".autopatch", "__pycache__"},
    )
    for index, (cwe, patcher, source) in enumerate(cases):
        project = tmp_path / f"case-{index}"
        project.mkdir()
        (project / "app.py").write_text(source, encoding="utf-8")
        finding = next(item for item in scanner.scan(project) if item.cwe == cwe)
        analysis = RuleBasedAnalyzer().analyze(project, finding)
        candidate = patcher.generate(project, finding, analysis)[0]
        SafePatchApplier().apply(project, candidate)

        result = verifier._exploit_mitigation(project, finding, candidate)

        assert result.status is StageStatus.PASS
        assert result.metadata["confirmed"] is True
