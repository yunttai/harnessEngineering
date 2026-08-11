from __future__ import annotations

from pathlib import Path

import pytest

from autopatch.config import HarnessSettings, load_settings
from autopatch.ui.common import validate_dast_target


def test_default_config_loads(repository_root: Path) -> None:
    settings = load_settings(repository_root / "config" / "harness.yaml")
    assert settings.project_name == "Attack2Patch"
    assert settings.scope.local_paths_only is True
    assert settings.autonomy.apply_patch is False
    assert [scanner.name for scanner in settings.detection.scanners] == [
        "builtin-python",
        "semgrep",
        "trivy",
        "gitleaks",
    ]


def test_deploy_requires_pr_gate() -> None:
    with pytest.raises(ValueError, match="create_pull_request"):
        HarnessSettings.model_validate(
            {
                "autonomy": {
                    "deploy": True,
                    "create_pull_request": False,
                }
            }
        )


def test_invalid_redaction_regex_is_rejected() -> None:
    with pytest.raises(ValueError, match="invalid redaction regex"):
        HarnessSettings.model_validate({"logging": {"redact_patterns": ["("]}})


def test_dast_requires_explicit_authorized_target() -> None:
    settings = HarnessSettings.model_validate(
        {"dast": {"enabled": True, "authorized_targets": ["https://staging.example.test"]}}
    )
    assert validate_dast_target("https://staging.example.test", settings) == (
        "https://staging.example.test"
    )
    with pytest.raises(PermissionError, match="not explicitly authorized"):
        validate_dast_target("https://production.example.test", settings)
