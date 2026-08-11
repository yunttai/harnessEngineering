from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from autopatch.config import HarnessSettings, load_settings
from autopatch.ui.cli import publish
from autopatch.ui.common import validate_dast_target


def test_default_config_loads(repository_root: Path) -> None:
    settings = load_settings(repository_root / "config" / "harness.yaml")
    assert settings.project_name == "Attack2Patch"
    assert settings.scope.local_paths_only is True
    assert settings.autonomy.apply_patch is True
    assert settings.autonomy.create_branch is True
    assert settings.autonomy.create_commit is True
    assert settings.autonomy.push_branch is True
    assert settings.autonomy.create_pull_request is False
    assert settings.publishing.branch_name == "Attack2patch"
    assert settings.llm.enabled is True
    assert settings.llm.provider == "codex"
    assert settings.sandbox.provider == "local-copy"
    assert settings.sandbox.network_mode == "none"
    assert "@sha256:" in settings.sandbox.image
    assert "@sha256:" in (settings.dast.zap.docker_image or "")
    assert "@sha256:" in (settings.dast.nuclei.docker_image or "")
    assert [scanner.name for scanner in settings.detection.scanners] == [
        "builtin-python",
        "semgrep",
        "trivy",
        "gitleaks",
    ]


def test_publish_cli_defaults_to_commit_and_push() -> None:
    parameters = inspect.signature(publish).parameters
    assert parameters["commit"].default is True
    assert parameters["push"].default is True
    assert parameters["pull_request"].default is False


def test_production_config_requires_digest_pinned_docker_scanners(
    repository_root: Path,
) -> None:
    settings = load_settings(repository_root / "config" / "production.yaml")
    external = [
        scanner for scanner in settings.detection.scanners if scanner.name != "builtin-python"
    ]
    assert {scanner.name for scanner in external} == {"semgrep", "trivy", "gitleaks"}
    assert all(scanner.required for scanner in external)
    assert all(scanner.execution == "docker" for scanner in external)
    assert all("@sha256:" in (scanner.docker_image or "") for scanner in external)


def test_deploy_requires_push_gate() -> None:
    with pytest.raises(ValueError, match="push_branch"):
        HarnessSettings.model_validate(
            {
                "autonomy": {
                    "deploy": True,
                    "push_branch": False,
                    "create_commit": False,
                    "create_branch": False,
                }
            }
        )


def test_invalid_redaction_regex_is_rejected() -> None:
    with pytest.raises(ValueError, match="invalid redaction regex"):
        HarnessSettings.model_validate({"logging": {"redact_patterns": ["("]}})


@pytest.mark.parametrize("provider", ["codex", "opencode", "claude"])
def test_supported_llm_cli_provider_is_accepted(provider: str) -> None:
    settings = HarnessSettings.model_validate({"llm": {"provider": provider}})
    assert settings.llm.provider == provider


def test_http_llm_provider_is_rejected() -> None:
    with pytest.raises(ValueError, match="Input should be"):
        HarnessSettings.model_validate({"llm": {"provider": "openai-responses"}})


def test_dast_requires_explicit_authorized_target() -> None:
    settings = HarnessSettings.model_validate(
        {"dast": {"enabled": True, "authorized_targets": ["https://staging.example.test"]}}
    )
    assert validate_dast_target("https://staging.example.test", settings) == (
        "https://staging.example.test"
    )
    with pytest.raises(PermissionError, match="not explicitly authorized"):
        validate_dast_target("https://production.example.test", settings)


def test_sandbox_loopback_dast_still_requires_explicit_autonomy() -> None:
    with pytest.raises(ValueError, match="dast.enabled"):
        HarnessSettings.model_validate({"autonomy": {"execute_dast": True}})

    settings = HarnessSettings.model_validate(
        {
            "autonomy": {"execute_dast": True},
            "dast": {"enabled": True, "allow_sandbox_loopback": True},
            "sandbox": {"provider": "docker"},
        }
    )
    assert settings.dast.allow_sandbox_loopback is True


def test_dast_authorization_rejects_embedded_credentials_and_fragments() -> None:
    with pytest.raises(ValueError, match="unsupported DAST target"):
        HarnessSettings.model_validate(
            {
                "dast": {
                    "enabled": True,
                    "authorized_targets": ["https://user:secret@example.test/#fragment"],
                }
            }
        )


def test_sandbox_image_cannot_be_interpreted_as_a_docker_option() -> None:
    with pytest.raises(ValueError, match="Docker image reference"):
        HarnessSettings.model_validate({"sandbox": {"provider": "docker", "image": "--privileged"}})


def test_container_images_must_be_digest_pinned() -> None:
    with pytest.raises(ValueError, match="sha256 digest"):
        HarnessSettings.model_validate({"sandbox": {"image": "python:3.12-slim"}})
    with pytest.raises(ValueError, match="sha256 digest"):
        HarnessSettings.model_validate(
            {"dast": {"nuclei": {"executable": "nuclei", "docker_image": "nuclei:latest"}}}
        )
    with pytest.raises(ValueError, match="sha256 digest"):
        HarnessSettings.model_validate(
            {
                "detection": {
                    "scanners": [
                        {
                            "name": "semgrep",
                            "execution": "docker",
                            "docker_image": "semgrep/semgrep:latest",
                        }
                    ]
                }
            }
        )
