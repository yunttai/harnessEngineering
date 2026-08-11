from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from autopatch.config import HarnessSettings
from autopatch.providers import GitPublisher, PatchApplier, PullRequestPublisher
from autopatch.types import (
    CandidateEvaluation,
    FindingOutcome,
    PatchCandidate,
    PublishingResult,
    PullRequestRequest,
    RunReport,
    RunState,
)


@dataclass(frozen=True, slots=True)
class PublishOptions:
    create_commit: bool = True
    push_branch: bool = True
    create_pull_request: bool = False
    branch: str | None = None

    def validate(self) -> None:
        if self.create_pull_request and not self.push_branch:
            raise ValueError("pull request creation requires an approved push")
        if self.push_branch and not self.create_commit:
            raise ValueError("push requires an approved commit")


class PublishingService:
    """Apply verified candidates and publish only through independent approval gates."""

    def __init__(
        self,
        *,
        settings: HarnessSettings,
        git: GitPublisher,
        applier: PatchApplier,
        pull_requests: PullRequestPublisher | None = None,
    ) -> None:
        self.settings = settings
        self.git = git
        self.applier = applier
        self.pull_requests = pull_requests

    def publish(
        self,
        target: Path,
        report: RunReport,
        options: PublishOptions,
    ) -> PublishingResult:
        options.validate()
        target = target.resolve()
        selected = self._selected(report)
        if report.state is not RunState.VERIFIED or not selected:
            raise ValueError("only a VERIFIED run with selected candidates can be published")
        self._check_policy(options)
        self._assert_distinct_files(selected)
        self._assert_no_secret_material(selected)
        if not self.git.is_repository(target):
            raise ValueError("publish target is not a Git repository")
        if self.settings.autonomy.require_clean_git_tree and not self.git.is_clean(target):
            raise RuntimeError("publish requires a clean Git worktree before patch application")

        base_sha = self.git.current_sha(target)
        branch = options.branch or self._branch_name(report)
        self.git.create_branch(target, branch)
        for candidate in selected:
            self.applier.apply(target, candidate)

        result = PublishingResult(
            base_sha=base_sha,
            branch=branch,
            remote=self.settings.publishing.push_remote,
        )
        if not options.create_commit:
            return result

        files = sorted({file for candidate in selected for file in candidate.changed_files})
        result.commit_sha = self.git.commit(
            target,
            files,
            f"fix(security): remediate {len(selected)} verified finding(s)",
        )
        if not options.push_branch:
            return result

        self.git.push(target, self.settings.publishing.push_remote, branch)
        result.pushed = True
        if not options.create_pull_request:
            return result
        if self.pull_requests is None or not self.pull_requests.available():
            raise RuntimeError("configured GitHub App pull request provider is unavailable")
        repository = self.settings.publishing.github_app.repository
        if repository is None:
            raise ValueError("GitHub App repository is not configured")
        request = PullRequestRequest(
            repository=repository,
            head=branch,
            base=self.settings.publishing.github_app.base_branch,
            title=f"[Attack2Patch] Remediate {len(selected)} verified finding(s)",
            body=self._pull_request_body(report, selected, result),
            draft=self.settings.publishing.draft_pull_request,
        )
        result.pull_request = self.pull_requests.create_pull_request(request)
        return result

    def _check_policy(self, options: PublishOptions) -> None:
        autonomy = self.settings.autonomy
        if not autonomy.apply_patch or not autonomy.create_branch:
            raise PermissionError("publishing requires apply_patch and create_branch policy gates")
        if options.create_commit and not autonomy.create_commit:
            raise PermissionError("commit policy gate is disabled")
        if options.push_branch and not autonomy.push_branch:
            raise PermissionError("push policy gate is disabled")
        if options.create_pull_request and not autonomy.create_pull_request:
            raise PermissionError("pull request policy gate is disabled")

    def _branch_name(self, report: RunReport) -> str:
        del report
        return self.settings.publishing.branch_name

    @staticmethod
    def _selected(report: RunReport) -> list[PatchCandidate]:
        selected: list[PatchCandidate] = []
        for outcome in report.outcomes:
            if not outcome.selected_candidate_id:
                continue
            evaluation = PublishingService._selected_evaluation(outcome)
            if evaluation is None or not evaluation.verification.eligible:
                raise ValueError("selected candidate does not have eligible verification evidence")
            selected.append(evaluation.candidate)
        return selected

    @staticmethod
    def _selected_evaluation(outcome: FindingOutcome) -> CandidateEvaluation | None:
        return next(
            (
                item
                for item in outcome.evaluations
                if item.candidate.candidate_id == outcome.selected_candidate_id
            ),
            None,
        )

    @staticmethod
    def _assert_distinct_files(candidates: list[PatchCandidate]) -> None:
        owners: dict[str, str] = {}
        for candidate in candidates:
            for file in candidate.changed_files:
                previous = owners.setdefault(file, candidate.candidate_id)
                if previous != candidate.candidate_id:
                    raise ValueError(
                        f"multiple selected candidates edit {file}; combine and re-verify first"
                    )

    @staticmethod
    def _assert_no_secret_material(candidates: list[PatchCandidate]) -> None:
        patterns = (
            re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            re.compile(r"\bghp_[0-9A-Za-z]{36}\b"),
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        )
        replacements = "\n".join(
            edit.replacement for candidate in candidates for edit in candidate.edits
        )
        if any(pattern.search(replacements) for pattern in patterns):
            raise ValueError("candidate contains high-confidence secret material")

    def _pull_request_body(
        self,
        report: RunReport,
        candidates: list[PatchCandidate],
        result: PublishingResult,
    ) -> str:
        rows: list[str] = []
        for outcome in report.outcomes:
            evaluation = PublishingService._selected_evaluation(outcome)
            if evaluation is None:
                continue
            verification = evaluation.verification
            rows.append(
                "| "
                + " | ".join(
                    [
                        outcome.finding.finding_id,
                        outcome.finding.cwe,
                        str(verification.build.status.value),
                        str(verification.functional_test.status.value),
                        str(verification.security_rescan.status.value),
                        str(verification.exploit_test.status.value),
                        str(verification.score.total),
                    ]
                )
                + " |"
            )
        changed = ", ".join(sorted({file for item in candidates for file in item.changed_files}))
        repository = self.settings.publishing.github_app.repository or "owner/repository"
        web_url = self.settings.publishing.github_app.web_url.rstrip("/")
        ci_url = f"{web_url}/{repository}/actions?query=branch%3A{quote(result.branch, safe='')}"
        return "\n".join(
            [
                "## Attack2Patch verified remediation",
                "",
                f"- Run: `{report.run_id}`",
                f"- Base commit: `{result.base_sha}`",
                f"- Changed files: {changed}",
                f"- Evidence: `{report.artifact_dir or '.autopatch/runs/' + report.run_id}`",
                "",
                "| Finding | CWE | Build | Regression | Re-scan | Exploit | Score |",
                "| --- | --- | --- | --- | --- | --- | ---: |",
                *rows,
                "",
                "## Risk and rollback",
                "",
                "This is a draft PR. Review framework assumptions and any SKIPPED verification.",
                f"Rollback after merge: revert commit `{result.commit_sha or '<pending>'}`.",
                f"CI status: [branch workflow checks]({ci_url}) (pending).",
            ]
        )
