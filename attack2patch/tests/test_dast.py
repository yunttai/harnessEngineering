from __future__ import annotations

import json
from pathlib import Path

import pytest

from autopatch.config import DastSettings, DastToolSettings, SandboxSettings
from autopatch.runtime.command import CommandResult
from autopatch.runtime.dast import (
    NucleiDastProvider,
    ZapDastProvider,
    parse_nuclei_jsonl,
    parse_zap_json,
)
from autopatch.types import Severity, StageStatus


def test_nuclei_and_zap_outputs_are_normalized() -> None:
    nuclei = parse_nuclei_jsonl(
        json.dumps(
            {
                "template-id": "sqli-error-based",
                "matched-at": "http://127.0.0.1:8000/users?id=1",
                "info": {"name": "SQL injection", "severity": "high"},
            }
        )
    )
    zap = parse_zap_json(
        json.dumps(
            {
                "site": [
                    {
                        "@name": "http://127.0.0.1:8000",
                        "alerts": [
                            {
                                "pluginid": "40018",
                                "alert": "SQL Injection",
                                "riskdesc": "High (3)",
                                "instances": [
                                    {"uri": "http://127.0.0.1:8000/users", "param": "id"}
                                ],
                            }
                        ],
                    }
                ]
            }
        )
    )

    assert nuclei[0].severity is Severity.HIGH
    assert zap[0].severity is Severity.HIGH
    assert nuclei[0].fingerprint == parse_nuclei_jsonl(
        json.dumps(
            {
                "template-id": "sqli-error-based",
                "matched-at": "http://127.0.0.1:8000/users?id=1",
                "info": {"name": "SQL injection", "severity": "high"},
            }
        )
    )[0].fingerprint


class _NucleiRunner:
    def run(self, argv, *, cwd: Path, timeout_seconds: int, **_kwargs):
        return CommandResult(
            argv=list(argv),
            exit_code=0,
            stdout=json.dumps(
                {
                    "template-id": "http-misconfiguration",
                    "matched-at": "https://staging.example.test",
                    "info": {"name": "Misconfiguration", "severity": "medium"},
                }
            ),
            stderr="",
            duration_ms=5,
        )


def test_nuclei_provider_requires_exact_authorization() -> None:
    settings = DastSettings(
        enabled=True,
        authorized_targets=["https://staging.example.test"],
        nuclei=DastToolSettings(enabled=True, executable="nuclei"),
    )
    provider = NucleiDastProvider(
        settings,
        settings.nuclei,
        runner=_NucleiRunner(),
        executable_resolver=lambda _value: "nuclei",
    )

    result = provider.scan("https://staging.example.test")
    assert result.status is StageStatus.PASS
    assert len(result.findings) == 1

    with pytest.raises(PermissionError, match="not explicitly authorized"):
        provider.scan("https://production.example.test")

    settings.nuclei.extra_args = ["-u", "https://production.example.test"]
    with pytest.raises(ValueError, match="reserved option"):
        provider.scan("https://staging.example.test")


class _ZapRunner:
    def run(self, argv, *, cwd: Path, timeout_seconds: int, **_kwargs):
        report_name = argv[argv.index("-J") + 1]
        (cwd / report_name).write_text(
            json.dumps(
                {
                    "site": [
                        {
                            "@name": "https://staging.example.test",
                            "alerts": [
                                {
                                    "pluginid": "10021",
                                    "alert": "Missing header",
                                    "riskdesc": "Low (1)",
                                    "instances": [],
                                }
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return CommandResult(
            argv=list(argv),
            exit_code=1,
            stdout="",
            stderr="",
            duration_ms=7,
        )


def test_zap_provider_parses_report_even_when_alert_exit_code_is_nonzero() -> None:
    settings = DastSettings(
        enabled=True,
        authorized_targets=["https://staging.example.test"],
        zap=DastToolSettings(enabled=True, executable="zap-baseline.py"),
    )
    provider = ZapDastProvider(
        settings,
        settings.zap,
        runner=_ZapRunner(),
        executable_resolver=lambda _value: "zap-baseline.py",
    )

    result = provider.scan("https://staging.example.test")
    assert result.status is StageStatus.PASS
    assert result.findings[0].severity is Severity.LOW


class _DockerDastRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def run(self, argv, *, cwd: Path, timeout_seconds: int, **_kwargs):
        command = list(argv)
        self.commands.append(command)
        stdout = ""
        if command[1:3] == ["run", "--rm"]:
            if "zap-baseline.py" in command:
                (cwd / "zap-report.json").write_text('{"site": []}', encoding="utf-8")
            else:
                stdout = json.dumps(
                    {
                        "template-id": "custom-template",
                        "matched-at": "http://autopatch-app-test:8000",
                        "info": {"name": "Custom finding", "severity": "high"},
                    }
                )
        return CommandResult(
            argv=command,
            exit_code=0,
            stdout=stdout,
            stderr="",
            duration_ms=4,
        )


def _docker_only_resolver(value: str) -> str | None:
    return "docker" if value == "docker" else None


def test_nuclei_docker_provider_mounts_custom_template_read_only(tmp_path: Path) -> None:
    (tmp_path / "marker.yaml").write_text("id: marker\n", encoding="utf-8")
    tool = DastToolSettings(
        enabled=True,
        executable="nuclei",
        docker_image=(
            "projectdiscovery/nuclei@sha256:"
            "582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb"
        ),
    )
    settings = DastSettings(enabled=True, allow_sandbox_loopback=True, nuclei=tool)
    runner = _DockerDastRunner()
    provider = NucleiDastProvider(
        settings,
        tool,
        runner=runner,
        executable_resolver=_docker_only_resolver,
        sandbox_settings=SandboxSettings(provider="docker"),
    )

    result = provider.scan(
        "http://autopatch-app-test:8000",
        sandbox_target=True,
        network_name="autopatch-network-test",
        workspace=tmp_path,
        template="marker.yaml",
    )

    command = result.command
    assert result.status is StageStatus.PASS
    assert command[command.index("--network") + 1] == "autopatch-network-test"
    assert any("target=/workspace,readonly" in item for item in command)
    assert command[command.index("-t") + 1] == "/workspace/marker.yaml"
    assert runner.commands[-1][1:3] == ["rm", "-f"]


def test_zap_docker_provider_gives_unprivileged_home_bounded_tmpfs() -> None:
    tool = DastToolSettings(
        enabled=True,
        executable="zap-baseline.py",
        docker_image=(
            "ghcr.io/zaproxy/zaproxy@sha256:"
            "781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef"
        ),
    )
    settings = DastSettings(enabled=True, allow_sandbox_loopback=True, zap=tool)
    runner = _DockerDastRunner()
    provider = ZapDastProvider(
        settings,
        tool,
        runner=runner,
        executable_resolver=_docker_only_resolver,
        sandbox_settings=SandboxSettings(provider="docker", tmpfs_mb=128),
    )

    result = provider.scan(
        "http://autopatch-app-test:8000",
        sandbox_target=True,
        network_name="autopatch-network-test",
    )

    assert result.status is StageStatus.PASS
    assert any(
        item.startswith("/home/zap:rw,noexec,nosuid,uid=1000,gid=1000,mode=0700,")
        and item.endswith("size=512m")
        for item in result.command
    )
