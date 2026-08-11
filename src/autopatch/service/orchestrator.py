from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from autopatch.config import HarnessSettings
from autopatch.providers import (
    AnalysisProvider,
    PatchApplier,
    PatchProvider,
    VerificationProvider,
)
from autopatch.repo import ArtifactStore
from autopatch.service.detection import DetectionService
from autopatch.service.metrics import compute_run_metrics
from autopatch.types import (
    FindingOutcome,
    FindingStatus,
    PatchFeedback,
    PatchScore,
    RunReport,
    RunState,
    StageResult,
    StageStatus,
    VerificationReport,
    CandidateEvaluation,
)


class Orchestrator:
    def __init__(
        self,
        *,
        settings: HarnessSettings,
        config_path: Path,
        detection: DetectionService,
        analyzer: AnalysisProvider,
        patcher: PatchProvider,
        verifier: VerificationProvider,
        applier: PatchApplier,
        store: ArtifactStore,
    ) -> None:
        self.settings = settings
        self.config_path = config_path
        self.detection = detection
        self.analyzer = analyzer
        self.patcher = patcher
        self.verifier = verifier
        self.applier = applier
        self.store = store

    def run(self, target: Path, *, apply: bool = False) -> RunReport:
        target = target.resolve()
        if not target.is_dir():
            raise NotADirectoryError(target)

        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8]
        report = RunReport(
            run_id=run_id,
            target=str(target),
            config_path=str(self.config_path),
            dry_run=not apply,
        )
        report.transition(RunState.CREATED, "run created")

        report.transition(RunState.DETECTING, "scanner execution started")
        detection_result = self.detection.scan(target)
        report.findings = detection_result.findings
        report.scanner_errors = detection_result.errors
        report.metadata["scanner_skipped"] = detection_result.skipped
        report.metadata["scanner_executed"] = detection_result.executed
        self.store.write_findings(run_id, report.findings)

        if detection_result.errors:
            report.transition(
                RunState.FAILED,
                "required scanner failure",
                errors=detection_result.errors,
            )
            report.finished_at = datetime.now(timezone.utc)
            report.artifact_dir = str(self.store.write_run(report))
            return report

        report.transition(
            RunState.DETECTED,
            f"{len(report.findings)} normalized findings",
        )

        for finding in report.findings:
            report.transition(
                RunState.ANALYZING,
                f"analyzing {finding.finding_id}",
                finding_id=finding.finding_id,
            )
            try:
                analysis = self.analyzer.analyze(target, finding)
                finding.status = FindingStatus.ANALYZED
                self.store.write_analysis(run_id, finding.finding_id, analysis)
            except Exception as exc:
                report.outcomes.append(
                    FindingOutcome(
                        finding=finding,
                        status=FindingStatus.FAILED,
                        reason=f"analysis failed: {type(exc).__name__}: {exc}",
                    )
                )
                continue

            report.transition(
                RunState.PATCH_GENERATING,
                f"generating candidates for {finding.finding_id}",
                finding_id=finding.finding_id,
            )
            if finding.cwe not in self.settings.patching.supported_cwes:
                report.outcomes.append(
                    FindingOutcome(
                        finding=finding,
                        analysis=analysis,
                        status=FindingStatus.NEEDS_HUMAN_REVIEW,
                        reason=f"automatic patching is not enabled for {finding.cwe}",
                    )
                )
                continue

            feedback: list[PatchFeedback] = []
            evaluations: list[CandidateEvaluation] = []
            generated = []
            policy_rejected = []
            seen_candidate_ids: set[str] = set()
            patch_error: str | None = None

            for attempt in range(1, self.settings.autonomy.max_patch_attempts + 1):
                try:
                    attempt_candidates = self.patcher.generate(
                        target,
                        finding,
                        analysis,
                        feedback,
                    )
                except Exception as exc:
                    patch_error = f"patch generation failed: {type(exc).__name__}: {exc}"
                    break

                attempt_candidates = attempt_candidates[
                    : self.settings.patching.max_candidates_per_finding
                ]
                new_candidates = []
                for candidate in attempt_candidates:
                    if candidate.candidate_id in seen_candidate_ids:
                        continue
                    seen_candidate_ids.add(candidate.candidate_id)
                    candidate.metadata["attempt"] = attempt
                    generated.append(candidate)
                    if candidate.changed_lines > self.settings.patching.max_changed_lines:
                        policy_rejected.append(candidate)
                    else:
                        new_candidates.append(candidate)

                if not new_candidates:
                    break
                finding.status = FindingStatus.PATCH_GENERATED
                report.transition(
                    RunState.VERIFYING,
                    f"verifying {len(new_candidates)} candidates (attempt {attempt})",
                    finding_id=finding.finding_id,
                    attempt=attempt,
                )
                attempt_evaluations: list[CandidateEvaluation] = []
                for candidate in new_candidates:
                    try:
                        evaluation = self.verifier.verify(target, finding, candidate)
                    except Exception as exc:
                        evaluation = self._verification_error(finding.finding_id, candidate, exc)
                    attempt_evaluations.append(evaluation)
                    evaluations.append(evaluation)

                if any(item.verification.eligible for item in attempt_evaluations):
                    break
                feedback.extend(
                    self._feedback_for_attempt(
                        run_id,
                        finding.finding_id,
                        attempt,
                        attempt_evaluations,
                    )
                )

            self.store.write_candidates(run_id, finding.finding_id, generated)
            self.store.write_evaluations(run_id, finding.finding_id, evaluations)
            self.store.write_feedback(run_id, finding.finding_id, feedback)
            candidates = [
                candidate for candidate in generated if candidate not in policy_rejected
            ]
            if not candidates:
                report.outcomes.append(
                    FindingOutcome(
                        finding=finding,
                        analysis=analysis,
                        status=FindingStatus.NEEDS_HUMAN_REVIEW,
                        reason=(
                            "all candidates exceeded patch policy"
                            if policy_rejected
                            else patch_error or "no supported patch candidate"
                        ),
                    )
                )
                continue

            eligible = [evaluation for evaluation in evaluations if evaluation.verification.eligible]
            eligible.sort(
                key=lambda item: (
                    -item.verification.score.total,
                    item.candidate.changed_lines,
                    item.candidate.candidate_id,
                )
            )

            if not eligible:
                report.outcomes.append(
                    FindingOutcome(
                        finding=finding,
                        analysis=analysis,
                        evaluations=evaluations,
                        status=FindingStatus.NEEDS_HUMAN_REVIEW,
                        reason="all patch candidates failed verification",
                    )
                )
                continue

            selected = eligible[0]
            self.store.write_selected_diff(
                run_id,
                finding.finding_id,
                selected.candidate.unified_diff,
            )

            applied = False
            if apply:
                self.applier.apply(target, selected.candidate)
                applied = True
                finding.status = FindingStatus.APPLIED
            else:
                finding.status = FindingStatus.VERIFIED

            report.outcomes.append(
                FindingOutcome(
                    finding=finding,
                    analysis=analysis,
                    evaluations=evaluations,
                    selected_candidate_id=selected.candidate.candidate_id,
                    applied=applied,
                    status=finding.status,
                    reason=(
                        f"selected score={selected.verification.score.total}; "
                        f"confidence={selected.verification.confidence}"
                    ),
                )
            )

        if any(outcome.applied for outcome in report.outcomes):
            final_state = RunState.APPLIED
        elif any(outcome.status is FindingStatus.VERIFIED for outcome in report.outcomes):
            final_state = RunState.VERIFIED
        elif report.findings:
            final_state = RunState.NEEDS_HUMAN_REVIEW
        else:
            final_state = RunState.DETECTED

        report.transition(final_state, "pipeline completed")
        report.metrics = compute_run_metrics(report)
        report.finished_at = datetime.now(timezone.utc)
        report.artifact_dir = str(self.store.write_run(report))
        return report

    @staticmethod
    def _verification_error(
        finding_id: str,
        candidate,
        exc: Exception,
    ) -> CandidateEvaluation:
        error = StageResult(
            name="verification_provider",
            status=StageStatus.ERROR,
            reason=f"{type(exc).__name__}: {exc}",
        )
        verification = VerificationReport(
            candidate_id=candidate.candidate_id,
            finding_id=finding_id,
            build=error,
            functional_test=error,
            security_rescan=error,
            exploit_test=error,
            score=PatchScore(
                security_test=0,
                regression_test=0,
                code_change_size=0,
                build_stability=0,
                coding_style=0,
            ),
            eligible=False,
            confidence="none",
            rejection_reasons=["verification provider raised an exception"],
        )
        return CandidateEvaluation(candidate=candidate, verification=verification)

    @staticmethod
    def _feedback_for_attempt(
        run_id: str,
        finding_id: str,
        attempt: int,
        evaluations: list[CandidateEvaluation],
    ) -> list[PatchFeedback]:
        feedback: list[PatchFeedback] = []
        for evaluation in evaluations:
            report = evaluation.verification
            for stage in (
                report.build,
                report.functional_test,
                report.security_rescan,
                report.exploit_test,
            ):
                if stage.status is StageStatus.PASS:
                    continue
                feedback.append(
                    PatchFeedback(
                        attempt=attempt,
                        candidate_id=evaluation.candidate.candidate_id,
                        stage=stage.name,
                        status=stage.status,
                        reason=stage.reason,
                        command=stage.command,
                        exit_code=stage.exit_code,
                        stdout_excerpt=stage.stdout_excerpt,
                        stderr_excerpt=stage.stderr_excerpt,
                        artifact=(
                            f".autopatch/runs/{run_id}/finding-{finding_id}/evaluations.json"
                        ),
                    )
                )
        return feedback
