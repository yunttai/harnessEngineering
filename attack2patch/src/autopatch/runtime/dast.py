from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit
from uuid import uuid4

from autopatch.config import DastSettings, DastToolSettings, SandboxSettings
from autopatch.runtime.command import CommandResult, CommandRunner
from autopatch.runtime.sandbox import docker_security_flags
from autopatch.types import DastFinding, DastScanResult, Severity, StageStatus


_SEVERITIES = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}


def _severity(value: object) -> Severity:
    normalized = str(value or "").strip().lower()
    for label, severity in _SEVERITIES.items():
        if normalized == label or normalized.startswith(label + " "):
            return severity
    return Severity.UNKNOWN


def _fingerprint(tool: str, rule_id: str, url: str, message: str) -> str:
    payload = "\x1f".join((tool, rule_id, url, message)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def parse_nuclei_jsonl(payload: str) -> list[DastFinding]:
    findings: list[DastFinding] = []
    for line_number, raw_line in enumerate(payload.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid Nuclei JSONL at line {line_number}: {exc}") from exc
        if not isinstance(item, dict):
            raise ValueError(f"invalid Nuclei record at line {line_number}")
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        rule_id = str(item.get("template-id") or item.get("templateID") or "unknown")
        url = str(item.get("matched-at") or item.get("host") or "")
        message = str(info.get("name") or item.get("matcher-name") or rule_id)
        findings.append(
            DastFinding(
                fingerprint=_fingerprint("nuclei", rule_id, url, message),
                tool="nuclei",
                rule_id=rule_id,
                severity=_severity(info.get("severity")),
                url=url,
                message=message,
                evidence={
                    "type": item.get("type"),
                    "matcher_name": item.get("matcher-name"),
                    "extracted_results": item.get("extracted-results", []),
                },
            )
        )
    return findings


def parse_zap_json(payload: str) -> list[DastFinding]:
    try:
        root = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid ZAP JSON: {exc}") from exc
    if not isinstance(root, dict):
        raise ValueError("invalid ZAP report root")
    findings: list[DastFinding] = []
    sites = root.get("site", [])
    if not isinstance(sites, list):
        raise ValueError("invalid ZAP site list")
    for site in sites:
        if not isinstance(site, dict):
            continue
        alerts = site.get("alerts", [])
        if not isinstance(alerts, list):
            continue
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            rule_id = str(alert.get("pluginid") or alert.get("alertRef") or "unknown")
            message = str(alert.get("alert") or alert.get("name") or rule_id)
            severity = _severity(alert.get("riskdesc") or alert.get("riskcode"))
            instances = alert.get("instances", [])
            if not isinstance(instances, list) or not instances:
                instances = [{}]
            for instance in instances:
                if not isinstance(instance, dict):
                    instance = {}
                url = str(instance.get("uri") or site.get("@name") or "")
                findings.append(
                    DastFinding(
                        fingerprint=_fingerprint("zap", rule_id, url, message),
                        tool="zap",
                        rule_id=rule_id,
                        severity=severity,
                        url=url,
                        message=message,
                        evidence={
                            "parameter": instance.get("param"),
                            "attack": instance.get("attack"),
                            "evidence": instance.get("evidence"),
                            "confidence": alert.get("confidence"),
                        },
                    )
                )
    return findings


class _DastProviderBase:
    def __init__(
        self,
        settings: DastSettings,
        tool: DastToolSettings,
        *,
        runner: CommandRunner | None = None,
        executable_resolver: Callable[[str], str | None] | None = None,
        sandbox_settings: SandboxSettings | None = None,
    ) -> None:
        self.settings = settings
        self.tool = tool
        self.runner = runner or CommandRunner()
        self._resolve = executable_resolver or shutil.which
        self.sandbox_settings = sandbox_settings or SandboxSettings()

    def available(self) -> bool:
        return self._resolve(self.tool.executable) is not None or (
            self.tool.docker_image is not None
            and self._resolve(self.sandbox_settings.docker_executable) is not None
        )

    def _authorize(
        self,
        target: str,
        sandbox_target: bool,
        network_name: str | None,
    ) -> str:
        if not self.settings.enabled:
            raise PermissionError("DAST is disabled")
        parsed = urlsplit(target)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ValueError("DAST target must be an HTTP(S) URL")
        normalized = target.rstrip("/")
        authorized = {item.rstrip("/") for item in self.settings.authorized_targets}
        if normalized in authorized:
            return normalized
        if (
            sandbox_target
            and self.settings.allow_sandbox_loopback
            and (
                parsed.hostname in {"127.0.0.1", "localhost", "::1"}
                or (
                    network_name is not None
                    and network_name.startswith("autopatch-network-")
                    and parsed.hostname is not None
                    and parsed.hostname.startswith("autopatch-app-")
                )
            )
        ):
            return normalized
        raise PermissionError("DAST target is not explicitly authorized")

    def _reject_reserved_args(self, reserved: set[str]) -> None:
        for argument in self.tool.extra_args:
            option = argument.split("=", 1)[0]
            if option in reserved:
                raise ValueError(f"DAST extra_args cannot override reserved option: {option}")

    def _run_docker(
        self,
        inner_argv: list[str],
        *,
        cwd: Path,
        timeout_seconds: int,
        network_name: str | None,
        docker_args: list[str] | None = None,
    ) -> CommandResult:
        image = self.tool.docker_image
        if image is None:
            raise RuntimeError("DAST Docker execution requires docker_image")
        docker = self.sandbox_settings.docker_executable
        name = f"autopatch-dast-{uuid4().hex[:12]}"
        command = [
            docker,
            "run",
            "--rm",
            "--name",
            name,
            "--network",
            network_name or "bridge",
            *docker_security_flags(self.sandbox_settings),
            *(docker_args or []),
            image,
            *inner_argv,
        ]
        try:
            return self.runner.run(command, cwd=cwd, timeout_seconds=timeout_seconds)
        finally:
            self.runner.run(
                [docker, "rm", "-f", name],
                cwd=cwd,
                timeout_seconds=self.sandbox_settings.cleanup_timeout_seconds,
            )

    @staticmethod
    def _error_result(
        *,
        tool: str,
        target: str,
        command: list[str],
        exit_code: int | None,
        duration_ms: int,
        stdout: str,
        stderr: str,
        reason: str,
    ) -> DastScanResult:
        return DastScanResult(
            tool=tool,
            target=target,
            status=StageStatus.ERROR,
            command=command,
            exit_code=exit_code,
            duration_ms=duration_ms,
            stdout_excerpt=stdout,
            stderr_excerpt=stderr,
            reason=reason,
        )


class NucleiDastProvider(_DastProviderBase):
    name = "nuclei-dast"

    def scan(
        self,
        target: str,
        *,
        sandbox_target: bool = False,
        network_name: str | None = None,
        workspace: Path | None = None,
        template: str | None = None,
    ) -> DastScanResult:
        target = self._authorize(target, sandbox_target, network_name)
        self._reject_reserved_args({"-u", "-target", "-list", "-l", "-jsonl-export"})
        if not self.available():
            raise RuntimeError(f"Nuclei executable is unavailable: {self.tool.executable}")
        inner = [
            "-u",
            target,
            "-jsonl",
            "-silent",
            *self.tool.extra_args,
        ]
        docker_args: list[str] = []
        if template is not None:
            if workspace is None:
                raise ValueError("custom Nuclei template requires a workspace")
            workspace = workspace.resolve()
            template_path = (workspace / template).resolve()
            template_path.relative_to(workspace)
            if not template_path.is_file():
                raise FileNotFoundError(f"Nuclei template not found: {template}")
            if network_name is not None or self._resolve(self.tool.executable) is None:
                docker_args = [
                    "--mount",
                    f"type=bind,source={workspace},target=/workspace,readonly",
                ]
                inner.extend(["-t", f"/workspace/{template.replace(chr(92), '/')}"])
            else:
                inner.extend(["-t", str(template_path)])
        with tempfile.TemporaryDirectory(prefix="autopatch-nuclei-") as temp:
            directory = Path(temp)
            if network_name is not None or self._resolve(self.tool.executable) is None:
                result = self._run_docker(
                    inner,
                    cwd=directory,
                    timeout_seconds=self.tool.timeout_seconds,
                    network_name=network_name,
                    docker_args=docker_args,
                )
            else:
                result = self.runner.run(
                    [self.tool.executable, *inner],
                    cwd=directory,
                    timeout_seconds=self.tool.timeout_seconds,
                )
        if result.timed_out or result.exit_code != 0:
            return self._error_result(
                tool="nuclei",
                target=target,
                command=result.argv,
                exit_code=result.exit_code,
                duration_ms=result.duration_ms,
                stdout=result.stdout,
                stderr=result.stderr,
                reason="Nuclei timed out" if result.timed_out else "Nuclei scan failed",
            )
        try:
            findings = parse_nuclei_jsonl(result.stdout)
        except ValueError as exc:
            return self._error_result(
                tool="nuclei",
                target=target,
                command=result.argv,
                exit_code=result.exit_code,
                duration_ms=result.duration_ms,
                stdout=result.stdout,
                stderr=result.stderr,
                reason=str(exc),
            )
        return DastScanResult(
            tool="nuclei",
            target=target,
            status=StageStatus.PASS,
            findings=findings,
            command=result.argv,
            exit_code=result.exit_code,
            duration_ms=result.duration_ms,
            stdout_excerpt=result.stdout,
            stderr_excerpt=result.stderr,
        )


class ZapDastProvider(_DastProviderBase):
    name = "zap-dast"

    def scan(
        self,
        target: str,
        *,
        sandbox_target: bool = False,
        network_name: str | None = None,
        workspace: Path | None = None,
        template: str | None = None,
    ) -> DastScanResult:
        if template is not None:
            raise ValueError("custom DAST templates are supported only for nuclei")
        target = self._authorize(target, sandbox_target, network_name)
        self._reject_reserved_args({"-t", "-J"})
        if not self.available():
            raise RuntimeError(f"ZAP executable is unavailable: {self.tool.executable}")
        with tempfile.TemporaryDirectory(prefix="autopatch-zap-") as temp:
            directory = Path(temp)
            report = directory / "zap-report.json"
            zap_home_mb = max(self.sandbox_settings.tmpfs_mb, 512)
            inner = [
                "zap-baseline.py",
                "-t",
                target,
                "-J",
                report.name,
                "-I",
                *self.tool.extra_args,
            ]
            if network_name is not None or self._resolve(self.tool.executable) is None:
                result = self._run_docker(
                    inner,
                    cwd=directory,
                    timeout_seconds=self.tool.timeout_seconds,
                    network_name=network_name,
                    docker_args=[
                        "--mount",
                        f"type=bind,source={directory.resolve()},target=/zap/wrk",
                        "--tmpfs",
                        (
                            "/home/zap:rw,noexec,nosuid,uid=1000,gid=1000,mode=0700,"
                            f"size={zap_home_mb}m"
                        ),
                        "--workdir",
                        "/zap/wrk",
                    ],
                )
            else:
                result = self.runner.run(
                    [self.tool.executable, *inner[1:]],
                    cwd=directory,
                    timeout_seconds=self.tool.timeout_seconds,
                )
            if result.timed_out or result.exit_code not in {0, 1, 2}:
                return self._error_result(
                    tool="zap",
                    target=target,
                    command=result.argv,
                    exit_code=result.exit_code,
                    duration_ms=result.duration_ms,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    reason="ZAP timed out" if result.timed_out else "ZAP scan failed",
                )
            try:
                findings = parse_zap_json(report.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                return self._error_result(
                    tool="zap",
                    target=target,
                    command=result.argv,
                    exit_code=result.exit_code,
                    duration_ms=result.duration_ms,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    reason=f"ZAP report error: {exc}",
                )
        return DastScanResult(
            tool="zap",
            target=target,
            status=StageStatus.PASS,
            findings=findings,
            command=result.argv,
            exit_code=result.exit_code,
            duration_ms=result.duration_ms,
            stdout_excerpt=result.stdout,
            stderr_excerpt=result.stderr,
        )


def result_as_evidence(result: DastScanResult) -> dict[str, Any]:
    return result.model_dump(mode="json")
