from __future__ import annotations

import re
from pathlib import Path

from autopatch.runtime.command import CommandRunner


class LocalGitPublisher:
    """Local branch/commit helper. Remote push and PR remain explicit higher-level actions."""

    name = "local-git-publisher"

    def __init__(self, runner: CommandRunner | None = None) -> None:
        self.runner = runner or CommandRunner()

    def is_repository(self, target: Path) -> bool:
        result = self.runner.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=target,
            timeout_seconds=15,
        )
        return result.exit_code == 0 and result.stdout.strip() == "true"

    def is_clean(self, target: Path) -> bool:
        result = self.runner.run(
            ["git", "status", "--porcelain"],
            cwd=target,
            timeout_seconds=15,
        )
        if result.exit_code != 0:
            raise RuntimeError(result.stderr)
        return not result.stdout.strip()

    def create_branch(self, target: Path, branch: str) -> None:
        if not re.fullmatch(r"[A-Za-z0-9._/-]+", branch) or ".." in branch:
            raise ValueError("unsafe branch name")
        result = self.runner.run(
            ["git", "switch", "-c", branch],
            cwd=target,
            timeout_seconds=30,
        )
        if result.exit_code != 0:
            raise RuntimeError(result.stderr)

    def current_sha(self, target: Path) -> str:
        result = self.runner.run(
            ["git", "rev-parse", "HEAD"],
            cwd=target,
            timeout_seconds=15,
        )
        if result.exit_code != 0:
            raise RuntimeError(result.stderr)
        return result.stdout.strip()

    def commit(self, target: Path, files: list[str], message: str) -> str:
        if not files:
            raise ValueError("no files to commit")
        add = self.runner.run(
            ["git", "add", "--", *files],
            cwd=target,
            timeout_seconds=30,
        )
        if add.exit_code != 0:
            raise RuntimeError(add.stderr)
        commit = self.runner.run(
            ["git", "commit", "-m", message],
            cwd=target,
            timeout_seconds=60,
        )
        if commit.exit_code != 0:
            raise RuntimeError(commit.stderr)
        sha = self.runner.run(
            ["git", "rev-parse", "HEAD"],
            cwd=target,
            timeout_seconds=15,
        )
        if sha.exit_code != 0:
            raise RuntimeError(sha.stderr)
        return sha.stdout.strip()

    def push(self, target: Path, remote: str, branch: str) -> None:
        if not re.fullmatch(r"[A-Za-z0-9._-]+", remote):
            raise ValueError("unsafe remote name")
        if not re.fullmatch(r"[A-Za-z0-9._/-]+", branch) or ".." in branch:
            raise ValueError("unsafe branch name")
        result = self.runner.run(
            ["git", "push", "--set-upstream", remote, branch],
            cwd=target,
            timeout_seconds=120,
        )
        if result.exit_code != 0:
            raise RuntimeError(result.stderr)
