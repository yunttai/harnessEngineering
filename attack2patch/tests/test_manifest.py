from __future__ import annotations

from pathlib import Path

import pytest

from autopatch.runtime.manifest import load_security_test_manifest
from autopatch.types import SecurityTestManifest


def test_manifest_is_parsed_through_strict_schema(repository_root: Path) -> None:
    manifest = load_security_test_manifest(repository_root / "examples" / "vulnerable_flask")

    assert manifest is not None
    assert manifest.version == 1
    assert manifest.tests[0].baseline_expected_exit_code == 1
    assert manifest.tests[0].expected_exit_code == 0


def test_manifest_rejects_dast_without_application() -> None:
    with pytest.raises(ValueError, match="application"):
        SecurityTestManifest.model_validate(
            {
                "version": 1,
                "dast": [
                    {
                        "id": "sql-injection",
                        "finding": "CWE-89",
                        "tool": "nuclei",
                    }
                ],
            }
        )


def test_manifest_rejects_shell_like_unknown_fields() -> None:
    with pytest.raises(ValueError, match="Extra inputs"):
        SecurityTestManifest.model_validate(
            {
                "version": 1,
                "tests": [
                    {
                        "id": "bad",
                        "finding": "*",
                        "command": ["python", "test.py"],
                        "shell": True,
                    }
                ],
            }
        )
