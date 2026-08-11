from __future__ import annotations

import json
from pathlib import Path

from autopatch.repo import ArtifactStore


def test_artifact_store_redacts_configured_and_default_secret_patterns(tmp_path: Path) -> None:
    store = ArtifactStore(
        tmp_path / "runs",
        redact_patterns=[r"(?i)password\s*=\s*\S+"],
    )
    path = tmp_path / "runs" / "value.json"
    store.write_json(
        path,
        {
            "log": "password=hunter2",
            "token": "ghp_" + ("a" * 36),
        },
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert "hunter2" not in payload["log"]
    assert "ghp_" not in payload["token"]
    assert payload["log"] == "<redacted>"
