from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path

from autopatch.config import DastSettings, DastToolSettings, SandboxSettings, load_settings
from autopatch.runtime.dast import NucleiDastProvider, ZapDastProvider
from autopatch.runtime.factory import build_detection_service
from autopatch.runtime.sandbox import (
    DockerApplicationRunner,
    DockerCommandRunner,
    prepare_container_workspace,
)
from autopatch.types import ApplicationSpec, ReadinessProbe, StageStatus

_APP = '''from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body = b"ready"
        elif self.path == "/vulnerable":
            body = b"vulnerable-marker"
        else:
            body = b"attack2patch"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, format, *args):
        return
HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
'''

_NUCLEI_TEMPLATE = '''id: autopatch-marker
info:
  name: Attack2Patch marker
  author: attack2patch
  severity: high
http:
  - method: GET
    path: ["{{BaseURL}}/vulnerable"]
    matchers:
      - type: word
        words: ["vulnerable-marker"]
'''


def _docker_architecture(docker: str) -> str:
    result = subprocess.run(  # noqa: S603 - trusted configured Docker argv, no shell
        [docker, "info", "--format", "{{.Architecture}}"],
        check=True,
        capture_output=True,
        text=True,
    )
    architecture = result.stdout.strip().lower()
    return {"x86_64": "amd64", "aarch64": "arm64"}.get(architecture, architecture)


def _pull(docker: str, images: list[str]) -> None:
    for image in images:
        if "@sha256:" not in image:
            raise ValueError(f"Docker smoke refuses an unpinned image: {image}")
        subprocess.run(  # noqa: S603 - digest-pinned image and argv execution
            [docker, "pull", image],
            check=True,
        )


def _assert_clean(docker: str) -> None:
    checks = (
        [docker, "ps", "-a", "--filter", "name=autopatch-", "--format", "{{.Names}}"],
        [docker, "network", "ls", "--filter", "name=autopatch-", "--format", "{{.Name}}"],
    )
    leftovers: list[str] = []
    for command in checks:
        result = subprocess.run(  # noqa: S603 - fixed Docker inspection argv
            command,
            check=True,
            capture_output=True,
            text=True,
        )
        leftovers.extend(line for line in result.stdout.splitlines() if line.strip())
    if leftovers:
        raise RuntimeError(f"Docker smoke left resources behind: {', '.join(leftovers)}")


def run_smoke(expected_arch: str) -> dict[str, object]:
    config_path = Path(__file__).resolve().parents[1] / "config" / "production.yaml"
    settings = load_settings(config_path)
    docker = settings.sandbox.docker_executable
    if shutil.which(docker) is None:
        raise RuntimeError(f"Docker executable is unavailable: {docker}")
    actual_arch = _docker_architecture(docker)
    if actual_arch != expected_arch:
        raise RuntimeError(f"Docker architecture is {actual_arch}, expected {expected_arch}")

    zap_image = settings.dast.zap.docker_image
    nuclei_image = settings.dast.nuclei.docker_image
    if zap_image is None or nuclei_image is None:
        raise ValueError("Docker smoke requires ZAP and Nuclei images")
    scanner_images = [
        scanner.docker_image
        for scanner in settings.detection.scanners
        if scanner.execution == "docker" and scanner.docker_image is not None
    ]
    images = [settings.sandbox.image, nuclei_image, zap_image, *scanner_images]
    _pull(docker, images)

    sandbox = SandboxSettings.model_validate(
        {**settings.sandbox.model_dump(), "provider": "docker", "memory_mb": 2048}
    )
    nuclei_tool = DastToolSettings.model_validate(
        {**settings.dast.nuclei.model_dump(), "enabled": True, "extra_args": ["-duc"]}
    )
    zap_tool = DastToolSettings.model_validate(
        {**settings.dast.zap.model_dump(), "enabled": True, "extra_args": ["-m", "1"]}
    )
    dast = DastSettings.model_validate(
        {
            **settings.dast.model_dump(),
            "enabled": True,
            "allow_sandbox_loopback": True,
            "nuclei": nuclei_tool.model_dump(),
            "zap": zap_tool.model_dump(),
        }
    )

    with tempfile.TemporaryDirectory(prefix="autopatch-docker-smoke-") as temp:
        root = Path(temp)
        source = root / "source"
        baseline = root / "baseline"
        patched = root / "patched"
        source.mkdir()
        (source / "app.py").write_text(_APP, encoding="utf-8")
        (source / "nuclei-marker.yaml").write_text(_NUCLEI_TEMPLATE, encoding="utf-8")

        detection = build_detection_service(settings=settings, config_path=config_path)
        detection_result = detection.scan(source)
        expected_scanners = {"builtin-python", "semgrep", "trivy", "gitleaks"}
        if detection_result.errors or detection_result.skipped:
            raise RuntimeError(
                "external scanner smoke did not execute cleanly: "
                f"errors={detection_result.errors} skipped={detection_result.skipped}"
            )
        if set(detection_result.executed) != expected_scanners:
            raise RuntimeError(
                f"scanner execution was {detection_result.executed}, expected "
                f"{sorted(expected_scanners)}"
            )
        shutil.copytree(source, baseline)
        shutil.copytree(source, patched)
        prepare_container_workspace(baseline)
        prepare_container_workspace(patched)
        (patched / "app.py").write_text(
            _APP.replace("vulnerable-marker", "safe-marker"),
            encoding="utf-8",
        )

        boundary = DockerCommandRunner(
            source=source,
            workspace=baseline,
            settings=sandbox,
        ).run(
            [
                "python",
                "-c",
                (
                    "from pathlib import Path; blocked=False\n"
                    "try:\n Path('/source/write-test').write_text('x')\n"
                    "except OSError:\n blocked=True\n"
                    "Path('/workspace/write-test').write_text('x')\n"
                    "assert blocked"
                ),
            ],
            cwd=baseline,
            timeout_seconds=30,
        )
        if boundary.exit_code != 0 or boundary.timed_out:
            raise RuntimeError(f"Docker mount boundary failed: {boundary.stderr}")

        application = ApplicationSpec(
            command=["python", "app.py"],
            container_port=8000,
            readiness=ReadinessProbe(path="/health", timeout_seconds=30),
        )
        nuclei = NucleiDastProvider(dast, nuclei_tool, sandbox_settings=sandbox)
        nuclei_counts: list[int] = []
        for workspace in (baseline, patched):
            launcher = DockerApplicationRunner(
                source=source,
                workspace=workspace,
                settings=sandbox,
            )
            with launcher.start(application) as session:
                result = nuclei.scan(
                    session.target,
                    sandbox_target=True,
                    network_name=session.network_name,
                    workspace=workspace,
                    template="nuclei-marker.yaml",
                )
            if result.status is not StageStatus.PASS:
                raise RuntimeError(f"Nuclei smoke failed: {result.reason}")
            nuclei_counts.append(len(result.findings))
        if nuclei_counts != [1, 0]:
            raise RuntimeError(f"Nuclei differential was {nuclei_counts}, expected [1, 0]")

        zap = ZapDastProvider(dast, zap_tool, sandbox_settings=sandbox)
        launcher = DockerApplicationRunner(
            source=source,
            workspace=baseline,
            settings=sandbox,
        )
        with launcher.start(application) as session:
            zap_result = zap.scan(
                session.target,
                sandbox_target=True,
                network_name=session.network_name,
                workspace=baseline,
            )
        if zap_result.status is not StageStatus.PASS:
            raise RuntimeError(f"ZAP smoke failed: {zap_result.reason}")

    _assert_clean(docker)
    return {
        "host_machine": platform.machine(),
        "docker_architecture": actual_arch,
        "images": images,
        "scanners_executed": detection_result.executed,
        "scanner_errors": detection_result.errors,
        "source_read_only": True,
        "workspace_writable": True,
        "nuclei_findings": {"baseline": nuclei_counts[0], "patched": nuclei_counts[1]},
        "zap_findings": len(zap_result.findings),
        "leftover_resources": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-arch", required=True, choices=("amd64", "arm64"))
    args = parser.parse_args()
    print(json.dumps(run_smoke(args.expected_arch), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
