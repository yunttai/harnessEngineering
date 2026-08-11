#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = ROOT.parent
sys.path.insert(0, str(ROOT / "src"))

from autopatch.config import load_settings  # noqa: E402

PINNED_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
PINNED_ACTION = re.compile(r"^actions/(?:checkout|setup-python)@[0-9a-f]{40}$")


def main() -> int:
    settings = load_settings(ROOT / "config" / "harness.yaml")
    production = load_settings(ROOT / "config" / "production.yaml")
    images = [
        settings.sandbox.image,
        settings.dast.zap.docker_image,
        settings.dast.nuclei.docker_image,
        *[
            scanner.docker_image
            for scanner in production.detection.scanners
            if scanner.execution == "docker"
        ],
    ]
    invalid = [image for image in images if image is None or not PINNED_IMAGE.fullmatch(image)]
    if invalid:
        print(f"[production-policy] unpinned Docker images: {invalid}")
        return 1
    dockerfile_base = (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()[0]
    if not dockerfile_base.startswith("FROM ") or not PINNED_IMAGE.fullmatch(
        dockerfile_base.removeprefix("FROM ").strip()
    ):
        print("[production-policy] Dockerfile base image must use a sha256 digest")
        return 1
    if "--constraint constraints.txt" not in (ROOT / "Dockerfile").read_text(
        encoding="utf-8"
    ):
        print("[production-policy] Dockerfile must install with constraints.txt")
        return 1

    workflow_path = REPOSITORY_ROOT / ".github" / "workflows" / "harness.yml"
    workflow_text = workflow_path.read_text(encoding="utf-8")
    action_uses = [
        line.split("uses:", 1)[1].split("#", 1)[0].strip()
        for line in workflow_text.splitlines()
        if "uses: actions/" in line
    ]
    if not action_uses or any(PINNED_ACTION.fullmatch(item) is None for item in action_uses):
        print("[production-policy] GitHub Actions must be pinned to full commit SHAs")
        return 1
    if "pip install --constraint constraints.txt" not in workflow_text:
        print("[production-policy] CI dependency installation must use constraints.txt")
        return 1
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    jobs = workflow.get("jobs", {}) if isinstance(workflow, dict) else {}
    docker_job = jobs.get("docker-smoke", {}) if isinstance(jobs, dict) else {}
    matrix = docker_job.get("strategy", {}).get("matrix", {}).get("include", [])
    platforms = {
        (str(item.get("runner")), str(item.get("arch")))
        for item in matrix
        if isinstance(item, dict)
    }
    required = {("ubuntu-24.04", "amd64"), ("ubuntu-24.04-arm", "arm64")}
    if not required.issubset(platforms):
        print("[production-policy] Docker smoke matrix must cover amd64 and arm64")
        return 1
    verify_job = jobs.get("verify", {}) if isinstance(jobs, dict) else {}
    operating_systems = set(
        verify_job.get("strategy", {}).get("matrix", {}).get("os", [])
    )
    required_operating_systems = {"ubuntu-24.04", "windows-2025", "macos-15"}
    if not required_operating_systems.issubset(operating_systems):
        print("[production-policy] harness matrix must cover Linux, Windows, and macOS")
        return 1
    print("[production-policy] image digests and OS/architecture matrices are pinned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
