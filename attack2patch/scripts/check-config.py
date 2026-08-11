#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from autopatch.config import load_settings  # noqa: E402


def main() -> int:
    settings = load_settings(ROOT / "config" / "harness.yaml")
    tools = yaml.safe_load((ROOT / "config" / "tools.yaml").read_text(encoding="utf-8"))
    policy = yaml.safe_load(
        (ROOT / "config" / "policies" / "default.yaml").read_text(encoding="utf-8")
    )
    if tools.get("version") != 1 or not isinstance(tools.get("tools"), dict):
        raise ValueError("config/tools.yaml must contain version: 1 and a tools mapping")
    if policy.get("version") != 1 or policy.get("patch", {}).get("default_mode") != "dry-run":
        raise ValueError("default policy must remain version 1 and dry-run")
    if not settings.scope.local_paths_only:
        raise ValueError("MVP configuration must keep local_paths_only enabled")
    runbook = (ROOT / settings.deployment.rollback_runbook).resolve()
    try:
        runbook.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError("deployment rollback runbook must stay inside the product root") from exc
    if not runbook.is_file():
        raise FileNotFoundError(f"deployment rollback runbook not found: {runbook}")
    print(
        "[config] valid: "
        f"project={settings.project_name}, scanners={len(settings.detection.scanners)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
