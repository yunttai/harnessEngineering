from __future__ import annotations

import subprocess
from pathlib import Path

from autopatch.config import load_settings
from autopatch.runtime.factory import build_orchestrator
from autopatch.runtime.git_publisher import LocalGitPublisher
from autopatch.runtime.patch_apply import SafePatchApplier
from autopatch.service.publishing import PublishOptions, PublishingService


def _git(target: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=target,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def test_verified_run_defaults_to_attack2patch_branch_commit_and_push(
    vulnerable_project: Path,
    repository_root: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    remote = tmp_path / "remote.git"
    subprocess.run(
        ["git", "init", "--bare", str(remote)],
        capture_output=True,
        text=True,
        check=True,
    )
    _git(vulnerable_project, "init")
    _git(vulnerable_project, "config", "user.email", "attack2patch@example.invalid")
    _git(vulnerable_project, "config", "user.name", "Attack2Patch Test")
    _git(vulnerable_project, "add", ".")
    _git(vulnerable_project, "commit", "-m", "fixture")
    _git(vulnerable_project, "remote", "add", "origin", str(remote))

    config_path = repository_root / "config" / "harness.yaml"
    settings = load_settings(config_path)
    settings.llm.enabled = False
    settings.artifact_root = "artifacts"
    monkeypatch.chdir(tmp_path)
    report = build_orchestrator(
        settings=settings,
        config_path=config_path,
        execute_tests=True,
        execute_security_tests=True,
    ).run(vulnerable_project)

    service = PublishingService(
        settings=settings,
        git=LocalGitPublisher(),
        applier=SafePatchApplier(),
    )
    result = service.publish(
        vulnerable_project,
        report,
        PublishOptions(),
    )

    assert result.commit_sha == _git(vulnerable_project, "rev-parse", "HEAD")
    assert result.pushed is True
    assert _git(vulnerable_project, "branch", "--show-current") == "Attack2patch"
    assert _git(remote, "rev-parse", "refs/heads/Attack2patch") == result.commit_sha
    assert _git(vulnerable_project, "status", "--porcelain") == ""
    assert "cursor.execute(query, (user_id,))" in (
        vulnerable_project / "app.py"
    ).read_text(encoding="utf-8")
    body = service._pull_request_body(report, service._selected(report), result)
    assert "/actions?query=branch%3AAttack2patch" in body
