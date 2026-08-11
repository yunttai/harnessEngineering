from __future__ import annotations

import json
from pathlib import Path

from autopatch.config import load_settings
from autopatch.repo import ArtifactStore
from autopatch.runtime.builtin_patcher import BuiltinCwe89Patcher
from autopatch.runtime.builtin_scanner import BuiltinPythonScanner
from autopatch.runtime.patch_apply import SafePatchApplier
from autopatch.service.analysis import RuleBasedAnalyzer
from autopatch.service.detection import DetectionService
from autopatch.service.orchestrator import Orchestrator
from autopatch.types import (
    CandidateEvaluation,
    PatchCandidate,
    PatchScore,
    RunState,
    StageResult,
    StageStatus,
    VerificationReport,
)


class _FeedbackPatcher:
    name = "feedback-patcher"

    def __init__(self) -> None:
        self.delegate = BuiltinCwe89Patcher()
        self.feedback_seen: list[list[object]] = []

    def generate(self, target, finding, analysis, feedback=None) -> list[PatchCandidate]:
        self.feedback_seen.append(list(feedback or []))
        candidate = self.delegate.generate(target, finding, analysis)[0]
        if feedback:
            return [candidate.model_copy(update={"candidate_id": candidate.candidate_id + "-RETRY"})]
        return [candidate]


class _RetryVerifier:
    name = "retry-verifier"

    def verify(self, target, finding, candidate) -> CandidateEvaluation:
        retry = candidate.candidate_id.endswith("-RETRY")
        status = StageStatus.PASS if retry else StageStatus.FAIL
        build = StageResult(name="build", status=status, reason=None if retry else "compile failed")
        passed = StageResult(name="stage", status=StageStatus.PASS)
        verification = VerificationReport(
            candidate_id=candidate.candidate_id,
            finding_id=finding.finding_id,
            build=build,
            functional_test=passed,
            security_rescan=passed,
            exploit_test=passed,
            score=PatchScore(
                security_test=40,
                regression_test=30,
                code_change_size=15,
                build_stability=10 if retry else 0,
                coding_style=5,
            ),
            eligible=retry,
            confidence="full" if retry else "none",
            rejection_reasons=[] if retry else ["build=FAIL"],
        )
        return CandidateEvaluation(candidate=candidate, verification=verification)


def test_failed_stage_feedback_is_passed_to_bounded_retry(
    vulnerable_project: Path,
    repository_root: Path,
    tmp_path: Path,
) -> None:
    config_path = repository_root / "config" / "harness.yaml"
    settings = load_settings(config_path)
    settings.autonomy.max_patch_attempts = 2
    patcher = _FeedbackPatcher()
    store = ArtifactStore(tmp_path / "runs")
    orchestrator = Orchestrator(
        settings=settings,
        config_path=config_path,
        detection=DetectionService([BuiltinPythonScanner()]),
        analyzer=RuleBasedAnalyzer(),
        patcher=patcher,
        verifier=_RetryVerifier(),
        applier=SafePatchApplier(),
        store=store,
    )

    report = orchestrator.run(vulnerable_project)

    assert report.state is RunState.VERIFIED
    assert len(patcher.feedback_seen) == 2
    assert patcher.feedback_seen[1][0].stage == "build"
    assert patcher.feedback_seen[1][0].reason == "compile failed"
    feedback_path = Path(report.artifact_dir or "") / (
        f"finding-{report.findings[0].finding_id}/feedback.json"
    )
    payload = json.loads(feedback_path.read_text(encoding="utf-8"))
    assert payload[0]["attempt"] == 1
    assert payload[0]["stage"] == "build"
