from __future__ import annotations

from pathlib import Path

from autopatch.config import load_settings
from autopatch.runtime.factory import build_orchestrator
from autopatch.types import RunState


def test_orchestrator_dry_run_preserves_target(
    vulnerable_project: Path,
    repository_root: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = repository_root / "config" / "harness.yaml"
    settings = load_settings(config_path)
    settings.artifact_root = str(Path("artifacts"))
    monkeypatch.chdir(tmp_path)
    before = (vulnerable_project / "app.py").read_text(encoding="utf-8")

    orchestrator = build_orchestrator(
        settings=settings,
        config_path=config_path,
        execute_tests=True,
        execute_security_tests=True,
    )
    report = orchestrator.run(vulnerable_project, apply=False)

    assert report.state is RunState.VERIFIED
    assert report.dry_run is True
    assert report.outcomes[0].applied is False
    assert report.outcomes[0].evaluations[0].verification.score.total == 100
    assert report.metrics.patch_success_rate == 1.0
    assert report.metrics.security_fix_rate == 1.0
    assert report.metrics.regression_rate == 0.0
    assert report.metrics.exploit_mitigation_rate == 1.0
    assert (vulnerable_project / "app.py").read_text(encoding="utf-8") == before
    assert Path(report.artifact_dir or "").is_dir()


def test_orchestrator_applies_only_verified_candidate(
    vulnerable_project: Path,
    repository_root: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = repository_root / "config" / "harness.yaml"
    settings = load_settings(config_path)
    settings.artifact_root = "artifacts"
    monkeypatch.chdir(tmp_path)

    orchestrator = build_orchestrator(
        settings=settings,
        config_path=config_path,
        execute_tests=True,
        execute_security_tests=True,
    )
    report = orchestrator.run(vulnerable_project, apply=True)

    assert report.state is RunState.APPLIED
    assert report.outcomes[0].applied is True
    patched = (vulnerable_project / "app.py").read_text(encoding="utf-8")
    assert "cursor.execute(query, (user_id,))" in patched
    assert not orchestrator.detection.scan(vulnerable_project).findings
