from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any, Callable

from autopatch.runtime.command import CommandRunner
from autopatch.service.normalization import (
    finding_id_from_fingerprint,
    make_fingerprint,
    normalize_relative_path,
)
from autopatch.types import Evidence, Finding, Severity


_SEVERITIES = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "ERROR": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "WARNING": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "NOTE": Severity.LOW,
    "INFO": Severity.INFO,
}


def _severity(value: object) -> Severity:
    return _SEVERITIES.get(str(value or "").upper(), Severity.UNKNOWN)


def _cwe(values: object, default: str = "CWE-UNKNOWN") -> str:
    if isinstance(values, list):
        values = " ".join(str(value) for value in values)
    match = re.search(r"CWE-\d+", str(values or ""), re.IGNORECASE)
    return f"CWE-{int(match.group(0).split('-')[1])}" if match else default


def _relative(target: Path, value: object) -> str:
    raw = str(value or "unknown")
    path = Path(raw)
    if path.is_absolute():
        return path.resolve().relative_to(target.resolve()).as_posix()
    return normalize_relative_path(raw)


def _finding(
    *,
    scanner: str,
    rule_id: str,
    cwe: str,
    severity: Severity,
    file: str,
    line: int,
    end_line: int | None,
    message: str,
    raw_excerpt: str = "",
    metadata: dict[str, Any] | None = None,
) -> Finding:
    fingerprint = make_fingerprint(
        scanner=scanner,
        rule_id=rule_id,
        cwe=cwe,
        file=file,
        line=max(1, line),
        semantic_key=rule_id,
    )
    evidence = Evidence(
        scanner=scanner,
        rule_id=rule_id,
        message=message,
        file=file,
        line=max(1, line),
        raw_excerpt=raw_excerpt[:1000] or None,
        metadata=metadata or {},
    )
    return Finding(
        finding_id=finding_id_from_fingerprint(fingerprint),
        fingerprint=fingerprint,
        type=message,
        cwe=cwe,
        severity=severity,
        file=file,
        line=max(1, line),
        end_line=max(1, end_line or line),
        scanner=scanner,
        rule_id=rule_id,
        message=message,
        evidence=[evidence],
        metadata=metadata or {},
    )


def parse_sarif(target: Path, payload: object, *, scanner: str = "sarif") -> list[Finding]:
    if not isinstance(payload, dict):
        raise ValueError("SARIF root must be an object")
    findings: list[Finding] = []
    for run in payload.get("runs") or []:
        if not isinstance(run, dict):
            continue
        driver = ((run.get("tool") or {}).get("driver") or {})
        rules = {
            str(rule.get("id")): rule
            for rule in driver.get("rules") or []
            if isinstance(rule, dict) and rule.get("id")
        }
        scanner_name = str(driver.get("name") or scanner)
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            locations = result.get("locations") or []
            if not locations:
                continue
            physical = (locations[0].get("physicalLocation") or {})
            artifact = physical.get("artifactLocation") or {}
            region = physical.get("region") or {}
            rule_id = str(result.get("ruleId") or "sarif.unknown")
            rule = rules.get(rule_id, {})
            properties = {**(rule.get("properties") or {}), **(result.get("properties") or {})}
            tags = properties.get("tags") or []
            message_value = result.get("message") or {}
            message = str(message_value.get("text") or message_value.get("markdown") or rule_id)
            relative = _relative(target, artifact.get("uri"))
            findings.append(
                _finding(
                    scanner=scanner_name,
                    rule_id=rule_id,
                    cwe=_cwe([tags, properties.get("cwe"), rule.get("helpUri")]),
                    severity=_severity(result.get("level")),
                    file=relative,
                    line=int(region.get("startLine") or 1),
                    end_line=int(region.get("endLine") or region.get("startLine") or 1),
                    message=message,
                    raw_excerpt=str(region.get("snippet", {}).get("text") or ""),
                    metadata={"help_uri": rule.get("helpUri"), "properties": properties},
                )
            )
    return findings


def parse_trivy(target: Path, payload: object) -> list[Finding]:
    if not isinstance(payload, dict):
        raise ValueError("Trivy root must be an object")
    findings: list[Finding] = []
    for result in payload.get("Results") or []:
        if not isinstance(result, dict):
            continue
        relative = _relative(target, result.get("Target") or "dependency-manifest")
        for item in result.get("Vulnerabilities") or []:
            if not isinstance(item, dict):
                continue
            rule_id = str(item.get("VulnerabilityID") or "trivy.unknown")
            package = str(item.get("PkgName") or "unknown package")
            message = str(item.get("Title") or f"Vulnerable dependency: {package}")
            findings.append(
                _finding(
                    scanner="trivy",
                    rule_id=rule_id,
                    cwe=_cwe(item.get("CweIDs")),
                    severity=_severity(item.get("Severity")),
                    file=relative,
                    line=1,
                    end_line=1,
                    message=message,
                    metadata={
                        "package": package,
                        "installed_version": item.get("InstalledVersion"),
                        "fixed_version": item.get("FixedVersion"),
                        "class": result.get("Class"),
                        "type": result.get("Type"),
                    },
                )
            )
    return findings


def parse_gitleaks(target: Path, payload: object) -> list[Finding]:
    if not isinstance(payload, list):
        raise ValueError("Gitleaks root must be a list")
    findings: list[Finding] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        relative = _relative(target, item.get("File"))
        rule_id = str(item.get("RuleID") or "gitleaks.unknown")
        description = str(item.get("Description") or "Hard-coded secret")
        findings.append(
            _finding(
                scanner="gitleaks",
                rule_id=rule_id,
                cwe="CWE-798",
                severity=Severity.HIGH,
                file=relative,
                line=int(item.get("StartLine") or 1),
                end_line=int(item.get("EndLine") or item.get("StartLine") or 1),
                message=description,
                # Never persist Match/Secret fields from the raw Gitleaks result.
                metadata={
                    "commit": item.get("Commit"),
                    "entropy": item.get("Entropy"),
                    "fingerprint": item.get("Fingerprint"),
                },
            )
        )
    return findings


class JsonCommandScanner:
    def __init__(
        self,
        *,
        name: str,
        argv: list[str],
        parser: Callable[[Path, object], list[Finding]],
        required: bool = False,
        timeout_seconds: int = 180,
        success_exit_codes: set[int] | None = None,
        runner: CommandRunner | None = None,
    ) -> None:
        self.name = name
        self.argv = argv
        self.parser = parser
        self.required = required
        self.timeout_seconds = timeout_seconds
        self.success_exit_codes = success_exit_codes or {0}
        self.runner = runner or CommandRunner()

    def available(self) -> bool:
        return bool(self.argv) and shutil.which(self.argv[0]) is not None

    def scan(self, target: Path) -> list[Finding]:
        result = self.runner.run(
            self.argv,
            cwd=target.resolve(),
            timeout_seconds=self.timeout_seconds,
        )
        if result.timed_out:
            raise TimeoutError(f"{self.name} timed out after {self.timeout_seconds}s")
        if result.exit_code not in self.success_exit_codes:
            raise RuntimeError(f"{self.name} failed with exit code {result.exit_code}")
        try:
            payload = json.loads(result.stdout or "null")
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid {self.name} JSON: {exc}") from exc
        return self.parser(target.resolve(), payload)


class TrivyScanner(JsonCommandScanner):
    def __init__(self, *, required: bool = False, timeout_seconds: int = 180) -> None:
        super().__init__(
            name="trivy",
            argv=["trivy", "fs", "--format", "json", "--quiet", "."],
            parser=parse_trivy,
            required=required,
            timeout_seconds=timeout_seconds,
        )


class GitleaksScanner(JsonCommandScanner):
    def __init__(self, *, required: bool = False, timeout_seconds: int = 180) -> None:
        super().__init__(
            name="gitleaks",
            argv=[
                "gitleaks",
                "detect",
                "--no-git",
                "--report-format",
                "json",
                "--report-path",
                "-",
            ],
            parser=parse_gitleaks,
            required=required,
            timeout_seconds=timeout_seconds,
            success_exit_codes={0, 1},
        )
