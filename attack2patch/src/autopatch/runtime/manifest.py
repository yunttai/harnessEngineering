from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from autopatch.types import SecurityTestManifest


MANIFEST_NAME = "autopatch-security-tests.yaml"
MAX_MANIFEST_BYTES = 1_048_576


def load_security_test_manifest(workspace: Path) -> SecurityTestManifest | None:
    """Parse the untrusted repository manifest through the strict Pydantic boundary."""

    workspace = workspace.resolve()
    path = (workspace / MANIFEST_NAME).resolve()
    path.relative_to(workspace)
    if not path.is_file():
        return None
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ValueError("security-test manifest exceeds 1 MiB")
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return SecurityTestManifest.model_validate(payload)
    except (OSError, yaml.YAMLError, ValidationError, ValueError) as exc:
        raise ValueError(f"invalid security-test manifest: {exc}") from exc
