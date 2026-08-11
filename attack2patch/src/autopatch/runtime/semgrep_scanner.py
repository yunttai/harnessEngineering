from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from autopatch.config import SandboxSettings
from autopatch.runtime.command import CommandRunner
from autopatch.runtime.scanner_container import DockerScannerRunner
from autopatch.service.normalization import (
    finding_id_from_fingerprint,
    make_fingerprint,
    normalize_relative_path,
)
from autopatch.types import Evidence, Finding, Severity

_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "INVENTORY": Severity.INFO,
    "EXPERIMENT": Severity.INFO,
}


class SemgrepScanner:
    name = "semgrep"

    def __init__(
        self,
        *,
        config_path: Path,
        required: bool = False,
        timeout_seconds: int = 180,
        execution: str = "auto",
        docker_image: str | None = None,
        docker_network: str = "none",
        sandbox_settings: SandboxSettings | None = None,
        runner: CommandRunner | None = None,
        docker_runner: DockerScannerRunner | None = None,
    ) -> None:
        self.config_path = config_path.resolve()
        self.required = required
        self.timeout_seconds = timeout_seconds
        self.execution = execution
        self.docker_image = docker_image
        self.docker_network = docker_network
        self.runner = runner or CommandRunner()
        self.docker_runner = docker_runner or DockerScannerRunner(
            sandbox_settings or SandboxSettings(),
            runner=self.runner,
        )

    def available(self) -> bool:
        return self.config_path.exists() and (
            self._native_available() or self._docker_available()
        )

    def _native_available(self) -> bool:
        return self.execution in {"auto", "native"} and shutil.which("semgrep") is not None

    def _docker_available(self) -> bool:
        return (
            self.execution in {"auto", "docker"}
            and self.docker_image is not None
            and self.docker_runner.available()
        )

    def scan(self, target: Path) -> list[Finding]:
        target = target.resolve()
        arguments = ["scan", "--json", "--metrics=off"]
        if self._native_available():
            result = self.runner.run(
                ["semgrep", *arguments, "--config", str(self.config_path), "."],
                cwd=target,
                timeout_seconds=self.timeout_seconds,
            )
        elif self._docker_available():
            assert self.docker_image is not None
            result = self.docker_runner.run(
                image=self.docker_image,
                argv=["semgrep", *arguments, "--config", "/rules", "."],
                target=target,
                timeout_seconds=self.timeout_seconds,
                network=self.docker_network,
                mounts=[(self.config_path, "/rules", True)],
            )
        else:
            raise RuntimeError("Semgrep is unavailable for the configured execution mode")
        if result.timed_out:
            raise TimeoutError(f"semgrep timed out after {self.timeout_seconds}s")
        if result.exit_code not in {0, 1}:
            raise RuntimeError(
                f"semgrep failed with exit code {result.exit_code}: {result.stderr}"
            )
        try:
            payload = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid semgrep JSON: {exc}") from exc

        findings: list[Finding] = []
        for item in payload.get("results", []):
            findings.append(self._normalize(target, item))
        return findings

    def _normalize(self, target: Path, item: dict[str, Any]) -> Finding:
        path_value = str(item.get("path", ""))
        path = Path(path_value)
        if path.is_absolute():
            relative = path.resolve().relative_to(target).as_posix()
        else:
            relative = normalize_relative_path(path.as_posix())

        start = item.get("start") or {}
        end = item.get("end") or {}
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        rule_id = str(item.get("check_id") or "semgrep.unknown")
        cwe = self._extract_cwe(metadata)
        line = int(start.get("line") or 1)
        message = str(extra.get("message") or rule_id)
        severity = _SEVERITY_MAP.get(str(extra.get("severity", "")).upper(), Severity.UNKNOWN)
        source = metadata.get("source")
        sink = metadata.get("sink")
        semantic = str(extra.get("lines") or message)[:500]
        fingerprint = make_fingerprint(
            scanner=self.name,
            rule_id=rule_id,
            cwe=cwe,
            file=relative,
            line=line,
            semantic_key=semantic,
        )
        evidence = Evidence(
            scanner=self.name,
            rule_id=rule_id,
            message=message,
            source=str(source) if source else None,
            sink=str(sink) if sink else None,
            file=relative,
            line=line,
            column=int(start.get("col") or 1),
            raw_excerpt=str(extra.get("lines") or "")[:1000],
            metadata={
                "semgrep_metadata": metadata,
                "end": end,
            },
        )
        return Finding(
            finding_id=finding_id_from_fingerprint(fingerprint),
            fingerprint=fingerprint,
            type=str(metadata.get("category") or message),
            cwe=cwe,
            severity=severity,
            file=relative,
            line=line,
            end_line=int(end.get("line") or line),
            function=None,
            source=str(source) if source else None,
            sink=str(sink) if sink else None,
            scanner=self.name,
            rule_id=rule_id,
            message=message,
            evidence=[evidence],
            metadata={"semgrep_metadata": metadata},
        )

    @staticmethod
    def _extract_cwe(metadata: dict[str, Any]) -> str:
        value = metadata.get("cwe")
        if isinstance(value, list) and value:
            value = value[0]
        text = str(value or "CWE-UNKNOWN")
        for token in text.replace(":", " ").split():
            if token.upper().startswith("CWE-"):
                return token.upper().rstrip(",")
        return "CWE-UNKNOWN"
