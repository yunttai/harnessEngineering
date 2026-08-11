from __future__ import annotations

import ast
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import yaml

from autopatch.config.settings import VerificationSettings
from autopatch.runtime.command import CommandResult, CommandRunner
from autopatch.runtime.patch_apply import SafePatchApplier
from autopatch.service.detection import DetectionService
from autopatch.service.scoring import score_candidate
from autopatch.types import (
    CandidateEvaluation,
    Finding,
    PatchCandidate,
    StageResult,
    StageStatus,
    VerificationReport,
)


class LocalCopyVerifier:
    name = "local-copy-verifier"

    def __init__(
        self,
        *,
        detection: DetectionService,
        settings: VerificationSettings,
        excluded_directories: set[str],
        runner: CommandRunner | None = None,
        applier: SafePatchApplier | None = None,
    ) -> None:
        self.detection = detection
        self.settings = settings
        self.excluded_directories = excluded_directories
        self.runner = runner or CommandRunner()
        self.applier = applier or SafePatchApplier()

    def verify(
        self,
        target: Path,
        finding: Finding,
        candidate: PatchCandidate,
    ) -> CandidateEvaluation:
        with tempfile.TemporaryDirectory(prefix="autopatch-verify-") as temp:
            sandbox = Path(temp) / "workspace"
            self._copy_target(target.resolve(), sandbox)
            try:
                self.applier.apply(sandbox, candidate)
            except Exception as exc:
                error = StageResult(
                    name="candidate_apply",
                    status=StageStatus.ERROR,
                    reason=f"{type(exc).__name__}: {exc}",
                )
                score = score_candidate(candidate, error, error, error, error)
                verification = VerificationReport(
                    candidate_id=candidate.candidate_id,
                    finding_id=finding.finding_id,
                    build=error,
                    functional_test=error,
                    security_rescan=error,
                    exploit_test=error,
                    score=score,
                    eligible=False,
                    confidence="none",
                    rejection_reasons=["candidate could not be applied in sandbox"],
                )
                return CandidateEvaluation(candidate=candidate, verification=verification)

            build = self._build(sandbox)
            functional = self._functional_test(sandbox)
            rescan = self._security_rescan(sandbox, finding)
            exploit = self._exploit_mitigation(sandbox, finding, candidate)
            score = score_candidate(candidate, build, functional, rescan, exploit)

            rejection_reasons: list[str] = []
            if self.settings.require_build_pass and build.status is not StageStatus.PASS:
                rejection_reasons.append(f"build={build.status}")
            if (
                self.settings.require_regression_not_failed
                and functional.status in {StageStatus.FAIL, StageStatus.ERROR}
            ):
                rejection_reasons.append(f"functional_test={functional.status}")
            if (
                self.settings.require_security_rescan_pass
                and rescan.status is not StageStatus.PASS
            ):
                rejection_reasons.append(f"security_rescan={rescan.status}")
            if (
                self.settings.require_exploit_not_failed
                and exploit.status in {StageStatus.FAIL, StageStatus.ERROR}
            ):
                rejection_reasons.append(f"exploit_test={exploit.status}")

            eligible = not rejection_reasons
            stages = [build, functional, rescan, exploit]
            if eligible and all(stage.status is StageStatus.PASS for stage in stages):
                confidence = "full"
            elif eligible:
                confidence = "limited"
            else:
                confidence = "none"

            verification = VerificationReport(
                candidate_id=candidate.candidate_id,
                finding_id=finding.finding_id,
                build=build,
                functional_test=functional,
                security_rescan=rescan,
                exploit_test=exploit,
                score=score,
                eligible=eligible,
                confidence=confidence,
                rejection_reasons=rejection_reasons,
            )
            return CandidateEvaluation(candidate=candidate, verification=verification)

    def _copy_target(self, source: Path, destination: Path) -> None:
        excluded = self.excluded_directories

        def ignore(_directory: str, names: list[str]) -> set[str]:
            return {name for name in names if name in excluded}

        shutil.copytree(source, destination, symlinks=True, ignore=ignore)

    def _build(self, sandbox: Path) -> StageResult:
        if not any(sandbox.rglob("*.py")):
            return StageResult(
                name="build",
                status=StageStatus.SKIPPED,
                reason="no Python files",
            )
        result = self.runner.run(
            [sys.executable, "-m", "compileall", "-q", "."],
            cwd=sandbox,
            timeout_seconds=self.settings.build_timeout_seconds,
        )
        return self._stage_from_command("build", result)

    def _functional_test(self, sandbox: Path) -> StageResult:
        if not self.settings.execute_project_tests:
            return StageResult(
                name="functional_test",
                status=StageStatus.SKIPPED,
                reason="project test execution is disabled; use --execute-tests for trusted targets",
            )
        has_tests = (
            (sandbox / "tests").is_dir()
            or any(sandbox.glob("test_*.py"))
            or any(sandbox.rglob("test_*.py"))
        )
        if not has_tests:
            return StageResult(
                name="functional_test",
                status=StageStatus.SKIPPED,
                reason="no test suite detected",
            )
        result = self.runner.run(
            [sys.executable, "-m", "pytest", "-q"],
            cwd=sandbox,
            timeout_seconds=self.settings.test_timeout_seconds,
        )
        return self._stage_from_command("functional_test", result)

    def _security_rescan(self, sandbox: Path, original: Finding) -> StageResult:
        started = time.monotonic()
        result = self.detection.scan(sandbox)
        duration = int((time.monotonic() - started) * 1000)
        if original.scanner not in result.executed:
            return StageResult(
                name="security_rescan",
                status=StageStatus.ERROR,
                duration_ms=duration,
                reason=f"original scanner {original.scanner} did not execute",
                metadata={
                    "executed": result.executed,
                    "errors": result.errors,
                    "skipped": result.skipped,
                },
            )
        if result.errors:
            return StageResult(
                name="security_rescan",
                status=StageStatus.ERROR,
                duration_ms=duration,
                reason="; ".join(result.errors),
                metadata={"skipped": result.skipped},
            )

        remaining = [
            finding
            for finding in result.findings
            if finding.file == original.file
            and finding.cwe == original.cwe
            and (
                finding.rule_id == original.rule_id
                or original.rule_id is None
                or finding.rule_id is None
            )
        ]
        if remaining:
            return StageResult(
                name="security_rescan",
                status=StageStatus.FAIL,
                duration_ms=duration,
                reason="same CWE/rule remains after patch",
                metadata={
                    "remaining_findings": [
                        item.model_dump(mode="json") for item in remaining
                    ],
                    "scanner_skipped": result.skipped,
                    "scanner_executed": result.executed,
                },
            )
        return StageResult(
            name="security_rescan",
            status=StageStatus.PASS,
            duration_ms=duration,
            reason="original CWE/rule no longer detected",
            metadata={
                "remaining_finding_count": len(result.findings),
                "scanner_skipped": result.skipped,
                "scanner_executed": result.executed,
            },
        )

    def _exploit_mitigation(
        self,
        sandbox: Path,
        finding: Finding,
        candidate: PatchCandidate,
    ) -> StageResult:
        started = time.monotonic()
        manifest_result = self._manifest_security_tests(sandbox, finding)
        if manifest_result is not None and manifest_result.status is not StageStatus.PASS:
            return manifest_result

        if finding.cwe != "CWE-89":
            if manifest_result is not None:
                return manifest_result
            return StageResult(
                name="exploit_test",
                status=StageStatus.SKIPPED,
                duration_ms=int((time.monotonic() - started) * 1000),
                reason="no built-in exploit oracle or matching security-test manifest",
            )

        query_variable = str(candidate.metadata.get("query_variable") or "")
        parameters = [str(value) for value in candidate.metadata.get("parameters", [])]
        if not query_variable or not parameters:
            return StageResult(
                name="exploit_test",
                status=StageStatus.ERROR,
                duration_ms=int((time.monotonic() - started) * 1000),
                reason="candidate lacks structured CWE-89 metadata",
                metadata=self._manifest_metadata(manifest_result),
            )

        path = (sandbox / finding.file).resolve()
        path.relative_to(sandbox.resolve())
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=finding.file)

        query_literal: str | None = None
        safe_execute = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if any(
                    isinstance(target, ast.Name) and target.id == query_variable
                    for target in node.targets
                ) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    query_literal = node.value.value
            if isinstance(node, ast.Call) and len(node.args) >= 2:
                call_name = ast.unparse(node.func).split(".")[-1]
                if call_name not in {"execute", "executemany"}:
                    continue
                if isinstance(node.args[0], ast.Name) and node.args[0].id == query_variable:
                    parameter_text = ast.unparse(node.args[1])
                    safe_execute = all(parameter in parameter_text for parameter in parameters)

        duration = int((time.monotonic() - started) * 1000)
        metadata: dict[str, Any] = {
            "oracle": "python-ast-parameterization",
            "query_variable": query_variable,
            "parameters": parameters,
        }
        metadata.update(self._manifest_metadata(manifest_result))

        if (
            query_literal is not None
            and "%s" in query_literal
            and all("{" + parameter + "}" not in query_literal for parameter in parameters)
            and safe_execute
        ):
            reason = "attacker-controlled values are structurally separated from SQL syntax"
            if manifest_result is not None:
                reason = "security-test manifest and structural SQL oracle both passed"
            return StageResult(
                name="exploit_test",
                status=StageStatus.PASS,
                duration_ms=duration,
                reason=reason,
                metadata=metadata,
            )
        metadata.update({"query_literal": query_literal, "safe_execute": safe_execute})
        return StageResult(
            name="exploit_test",
            status=StageStatus.FAIL,
            duration_ms=duration,
            reason="parameterized execution structure was not confirmed",
            metadata=metadata,
        )

    def _manifest_security_tests(
        self,
        sandbox: Path,
        finding: Finding,
    ) -> StageResult | None:
        if not self.settings.execute_project_security_tests:
            return None
        manifest = sandbox / "autopatch-security-tests.yaml"
        if not manifest.is_file():
            return None
        started = time.monotonic()
        try:
            payload = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
            entries = payload.get("tests", [])
            if not isinstance(entries, list):
                raise ValueError("tests must be a list")
        except (OSError, yaml.YAMLError, ValueError) as exc:
            return StageResult(
                name="exploit_test",
                status=StageStatus.ERROR,
                duration_ms=int((time.monotonic() - started) * 1000),
                reason=f"invalid security-test manifest: {exc}",
            )

        matching: list[dict[str, Any]] = []
        for raw in entries:
            if not isinstance(raw, dict):
                continue
            selector = str(raw.get("finding") or "")
            if selector in {finding.cwe, finding.finding_id, "*"}:
                matching.append(raw)
        if not matching:
            return None

        executed: list[dict[str, Any]] = []
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        for entry in matching:
            test_id = str(entry.get("id") or "unnamed")
            raw_command = entry.get("command")
            if not isinstance(raw_command, list) or not raw_command:
                return StageResult(
                    name="exploit_test",
                    status=StageStatus.ERROR,
                    duration_ms=int((time.monotonic() - started) * 1000),
                    reason=f"security test {test_id} has no command list",
                )
            command = [str(value) for value in raw_command]
            if command[0] in {"python", "python3"}:
                command[0] = sys.executable
            timeout = int(entry.get("timeout_seconds") or self.settings.exploit_timeout_seconds)
            expected = int(entry.get("expected_exit_code") or 0)
            result = self.runner.run(command, cwd=sandbox, timeout_seconds=timeout)
            executed.append(
                {
                    "id": test_id,
                    "command": result.argv,
                    "exit_code": result.exit_code,
                    "expected_exit_code": expected,
                    "timed_out": result.timed_out,
                    "duration_ms": result.duration_ms,
                }
            )
            if result.stdout:
                stdout_parts.append(f"[{test_id}]\n{result.stdout}")
            if result.stderr:
                stderr_parts.append(f"[{test_id}]\n{result.stderr}")
            if result.timed_out or result.exit_code != expected:
                return StageResult(
                    name="exploit_test",
                    status=StageStatus.ERROR if result.timed_out else StageStatus.FAIL,
                    command=result.argv,
                    exit_code=result.exit_code,
                    duration_ms=int((time.monotonic() - started) * 1000),
                    stdout_excerpt="\n".join(stdout_parts),
                    stderr_excerpt="\n".join(stderr_parts),
                    reason=(
                        f"security test {test_id} timed out"
                        if result.timed_out
                        else f"security test {test_id} exited {result.exit_code}, expected {expected}"
                    ),
                    metadata={"manifest": manifest.name, "tests": executed},
                )

        return StageResult(
            name="exploit_test",
            status=StageStatus.PASS,
            duration_ms=int((time.monotonic() - started) * 1000),
            stdout_excerpt="\n".join(stdout_parts),
            stderr_excerpt="\n".join(stderr_parts),
            reason=f"{len(executed)} manifest security test(s) passed",
            metadata={"manifest": manifest.name, "tests": executed},
        )

    @staticmethod
    def _manifest_metadata(result: StageResult | None) -> dict[str, Any]:
        if result is None:
            return {}
        return {
            "manifest_security_tests": result.metadata.get("tests", []),
            "manifest_stdout": result.stdout_excerpt,
            "manifest_stderr": result.stderr_excerpt,
        }

    @staticmethod
    def _stage_from_command(name: str, result: CommandResult) -> StageResult:
        if result.timed_out:
            status = StageStatus.ERROR
            reason = "command timed out"
        elif result.exit_code == 0:
            status = StageStatus.PASS
            reason = None
        else:
            status = StageStatus.FAIL
            reason = f"exit code {result.exit_code}"
        return StageResult(
            name=name,
            status=status,
            command=result.argv,
            exit_code=result.exit_code,
            duration_ms=result.duration_ms,
            stdout_excerpt=result.stdout,
            stderr_excerpt=result.stderr,
            reason=reason,
        )
