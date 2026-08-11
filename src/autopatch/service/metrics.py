from __future__ import annotations

from statistics import mean

from autopatch.types import FindingStatus, RunMetrics, RunReport, StageStatus


def compute_run_metrics(report: RunReport) -> RunMetrics:
    evaluations = [
        evaluation
        for outcome in report.outcomes
        for evaluation in outcome.evaluations
    ]
    total = len(evaluations)
    stages = [
        stage
        for evaluation in evaluations
        for stage in (
            evaluation.verification.build,
            evaluation.verification.functional_test,
            evaluation.verification.security_rescan,
            evaluation.verification.exploit_test,
        )
    ]
    exploit_observed = [
        item.verification.exploit_test
        for item in evaluations
        if item.verification.exploit_test.status is not StageStatus.SKIPPED
    ]
    retries = [
        max(
            (
                int(item.candidate.metadata.get("attempt", 1)) - 1
                for item in outcome.evaluations
            ),
            default=0,
        )
        for outcome in report.outcomes
    ]
    verified = sum(
        outcome.status in {FindingStatus.VERIFIED, FindingStatus.APPLIED}
        for outcome in report.outcomes
    )
    return RunMetrics(
        patch_success_rate=(
            sum(item.verification.eligible for item in evaluations) / total if total else None
        ),
        security_fix_rate=(
            sum(
                item.verification.security_rescan.status is StageStatus.PASS
                for item in evaluations
            )
            / total
            if total
            else None
        ),
        regression_rate=(
            sum(
                item.verification.functional_test.status
                in {StageStatus.FAIL, StageStatus.ERROR}
                for item in evaluations
            )
            / total
            if total
            else None
        ),
        exploit_mitigation_rate=(
            sum(item.status is StageStatus.PASS for item in exploit_observed)
            / len(exploit_observed)
            if exploit_observed
            else None
        ),
        autonomous_patch_rate=verified / len(report.findings) if report.findings else None,
        average_changed_lines=(
            mean(item.candidate.changed_lines for item in evaluations) if evaluations else None
        ),
        average_retry_count=mean(retries) if retries else None,
        verification_skipped_ratio=(
            sum(stage.status is StageStatus.SKIPPED for stage in stages) / len(stages)
            if stages
            else None
        ),
    )
