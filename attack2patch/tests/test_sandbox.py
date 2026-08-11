from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest

from autopatch.config import DastSettings, SandboxSettings, VerificationSettings, load_settings
from autopatch.runtime.builtin_scanner import BuiltinPythonScanner
from autopatch.runtime.command import CommandResult
from autopatch.runtime.factory import build_orchestrator
from autopatch.runtime.sandbox import (
    ApplicationSession,
    DockerApplicationRunner,
    DockerCommandRunner,
)
from autopatch.runtime.verifier import DockerSandboxVerifier
from autopatch.service.detection import DetectionService
from autopatch.types import DastFinding, DastScanResult, Severity, StageStatus


class _DockerRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def run(self, argv, *, cwd: Path, timeout_seconds: int, **_kwargs):
        command = list(argv)
        self.commands.append(command)
        stdout = ""
        if len(command) > 2 and command[1] == "port":
            stdout = "127.0.0.1:49152\n"
        elif "--detach" in command:
            stdout = "container-id\n"
        return CommandResult(
            argv=command,
            exit_code=0,
            stdout=stdout,
            stderr="",
            duration_ms=1,
        )


def test_docker_command_runner_enforces_resource_and_network_boundaries(tmp_path: Path) -> None:
    source = tmp_path / "source"
    workspace = tmp_path / "workspace"
    source.mkdir()
    workspace.mkdir()
    host = _DockerRunner()
    runner = DockerCommandRunner(
        source=source,
        workspace=workspace,
        settings=SandboxSettings(provider="docker"),
        runner=host,
        executable_resolver=lambda _value: "docker",
    )

    result = runner.run(["python", "-V"], cwd=workspace, timeout_seconds=10)
    command = result.argv
    assert command[:2] == ["docker", "run"]
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--pull") + 1] == "never"
    assert "--read-only" in command
    assert ["--cap-drop", "ALL"] == command[
        command.index("--cap-drop") : command.index("--cap-drop") + 2
    ]
    assert any("target=/source,readonly" in item for item in command)
    assert any("target=/workspace" in item and "readonly" not in item for item in command)
    assert host.commands[-1][1:3] == ["rm", "-f"]


def test_selected_docker_sandbox_never_falls_back_to_local_copy(
    repository_root: Path,
    monkeypatch,
) -> None:
    config_path = repository_root / "config" / "harness.yaml"
    settings = load_settings(config_path)
    settings.llm.enabled = False
    settings.sandbox.provider = "docker"
    settings.sandbox.docker_executable = "missing-docker"
    monkeypatch.setattr("autopatch.runtime.factory.shutil.which", lambda _value: None)

    with pytest.raises(RuntimeError, match="Docker sandbox executable is unavailable"):
        build_orchestrator(settings=settings, config_path=config_path)


def test_application_runner_uses_internal_network_readiness_and_cleanup(tmp_path: Path) -> None:
    source = tmp_path / "source"
    workspace = tmp_path / "workspace"
    source.mkdir()
    workspace.mkdir()
    host = _DockerRunner()
    launcher = DockerApplicationRunner(
        source=source,
        workspace=workspace,
        settings=SandboxSettings(provider="docker"),
        runner=host,
        readiness_probe=lambda url, status, network: (
            url.endswith(":8000/health")
            and status == 200
            and network.startswith("autopatch-network-")
        ),
    )
    from autopatch.types import ApplicationSpec, ReadinessProbe

    application = ApplicationSpec(
        command=["python", "app.py"],
        container_port=8000,
        readiness=ReadinessProbe(path="/health"),
    )
    with launcher.start(application) as session:
        assert session.target.startswith("http://autopatch-app-")
        assert session.target.endswith(":8000")

    assert host.commands[0][1:4] == ["network", "create", "--internal"]
    assert all("--publish" not in command for command in host.commands)
    assert host.commands[-2][1:3] == ["rm", "-f"]
    assert host.commands[-1][1:3] == ["network", "rm"]


class _FakeLauncher:
    @contextmanager
    def start(self, _application):
        yield ApplicationSession(
            target="http://autopatch-app-test:8000",
            container_name="autopatch-app-test",
            network_name="autopatch-network-test",
        )


class _DifferentialNuclei:
    name = "nuclei-dast"

    def __init__(self) -> None:
        self.calls = 0

    def available(self) -> bool:
        return True

    def scan(
        self,
        target: str,
        *,
        sandbox_target: bool = False,
        network_name: str | None = None,
        workspace: Path | None = None,
        template: str | None = None,
    ) -> DastScanResult:
        self.calls += 1
        findings = []
        if self.calls == 1:
            findings = [
                DastFinding(
                    fingerprint="baseline-sqli",
                    tool="nuclei",
                    rule_id="sqli",
                    severity=Severity.HIGH,
                    url=target,
                    message="SQL injection",
                )
            ]
        return DastScanResult(
            tool="nuclei",
            target=target,
            status=StageStatus.PASS,
            findings=findings,
        )


def test_docker_verifier_compares_before_and_after_dast(
    vulnerable_project: Path,
) -> None:
    (vulnerable_project / "autopatch-security-tests.yaml").write_text(
        """version: 1
application:
  command: [python, app.py]
  container_port: 8000
  readiness:
    path: /health
dast:
  - id: sql-injection
    finding: CWE-89
    tool: nuclei
    baseline_min_findings: 1
    patched_max_findings: 0
""",
        encoding="utf-8",
    )
    scanner = BuiltinPythonScanner()
    finding = next(item for item in scanner.scan(vulnerable_project) if item.cwe == "CWE-89")
    provider = _DifferentialNuclei()
    verifier = DockerSandboxVerifier(
        detection=DetectionService([scanner]),
        settings=VerificationSettings(),
        sandbox_settings=SandboxSettings(provider="docker"),
        dast_settings=DastSettings(enabled=True, allow_sandbox_loopback=True),
        dast_providers=[provider],
        execute_dast=True,
        excluded_directories={".git", ".autopatch"},
        application_runner_factory=lambda **_kwargs: _FakeLauncher(),
    )

    baseline = verifier._dast_phase(
        vulnerable_project,
        vulnerable_project,
        finding,
        phase="baseline",
    )
    patched = verifier._dast_phase(
        vulnerable_project,
        vulnerable_project,
        finding,
        phase="patched",
    )

    assert baseline is not None and baseline.status is StageStatus.PASS
    assert patched is not None and patched.status is StageStatus.PASS
    assert baseline.metadata["dast"][0]["finding_count"] == 1
    assert patched.metadata["dast"][0]["finding_count"] == 0
