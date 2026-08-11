from __future__ import annotations

import ast
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from autopatch.config import DastSettings, SandboxSettings, VerificationSettings
from autopatch.providers import DastProvider
from autopatch.runtime.command import CommandResult, CommandRunner
from autopatch.runtime.manifest import load_security_test_manifest
from autopatch.runtime.patch_apply import SafePatchApplier
from autopatch.runtime.sandbox import (
    DockerApplicationRunner,
    DockerCommandRunner,
    prepare_container_workspace,
)
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
    sandbox_kind = "local-copy"
    python_executable = sys.executable

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
        target = target.resolve()
        baseline = self._baseline_exploit(target, finding)
        with tempfile.TemporaryDirectory(prefix="autopatch-verify-") as temp:
            sandbox = Path(temp) / "workspace"
            self._copy_target(target, sandbox)
            runner = self._runner_for(target, sandbox)
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
                    exploit_baseline=baseline,
                    score=score,
                    eligible=False,
                    confidence="none",
                    rejection_reasons=["candidate could not be applied in sandbox"],
                )
                return CandidateEvaluation(candidate=candidate, verification=verification)

            build = self._build(sandbox, runner)
            functional = self._functional_test(sandbox, runner)
            rescan = self._security_rescan(sandbox, finding)
            exploit = self._exploit_mitigation(
                sandbox,
                finding,
                candidate,
                runner=runner,
                baseline=baseline,
                source=target,
            )
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
            if self.settings.require_differential_exploit:
                if baseline is None:
                    rejection_reasons.append("exploit_baseline=SKIPPED")
                elif baseline.status is not StageStatus.PASS:
                    rejection_reasons.append(f"exploit_baseline={baseline.status}")

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
                exploit_baseline=baseline,
                score=score,
                eligible=eligible,
                confidence=confidence,
                rejection_reasons=rejection_reasons,
                sandbox_kind=self.sandbox_kind,
            )
            return CandidateEvaluation(candidate=candidate, verification=verification)

    def _runner_for(self, source: Path, workspace: Path) -> CommandRunner:
        return self.runner

    def _baseline_exploit(self, target: Path, finding: Finding) -> StageResult | None:
        if not self.settings.execute_project_security_tests and not self._has_dynamic_dast():
            return None
        with tempfile.TemporaryDirectory(prefix="autopatch-baseline-") as temp:
            workspace = Path(temp) / "workspace"
            self._copy_target(target, workspace)
            runner = self._runner_for(target, workspace)
            manifest = self._manifest_security_tests(
                workspace,
                finding,
                runner=runner,
                phase="baseline",
            )
            dast = self._dast_phase(target, workspace, finding, phase="baseline")
            return self._combine_dynamic_results("exploit_baseline", manifest, dast)

    def _has_dynamic_dast(self) -> bool:
        return False

    def _dast_phase(
        self,
        source: Path,
        workspace: Path,
        finding: Finding,
        *,
        phase: str,
    ) -> StageResult | None:
        return None

    def _copy_target(self, source: Path, destination: Path) -> None:
        excluded = self.excluded_directories

        def ignore(_directory: str, names: list[str]) -> set[str]:
            return {name for name in names if name in excluded}

        shutil.copytree(source, destination, symlinks=True, ignore=ignore)

    def _build(self, sandbox: Path, runner: CommandRunner | None = None) -> StageResult:
        if not any(sandbox.rglob("*.py")):
            return StageResult(
                name="build",
                status=StageStatus.SKIPPED,
                reason="no Python files",
            )
        result = (runner or self.runner).run(
            [self.python_executable, "-m", "compileall", "-q", "."],
            cwd=sandbox,
            timeout_seconds=self.settings.build_timeout_seconds,
        )
        return self._stage_from_command("build", result)

    def _functional_test(
        self,
        sandbox: Path,
        runner: CommandRunner | None = None,
    ) -> StageResult:
        if not self.settings.execute_project_tests:
            return StageResult(
                name="functional_test",
                status=StageStatus.SKIPPED,
                reason=(
                    "project test execution is disabled; use --execute-tests "
                    "for trusted targets"
                ),
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
        command = list(
            self.settings.project_test_command
            or [self.python_executable, "-m", "pytest", "-q"]
        )
        if command[0] in {"python", "python3"}:
            command[0] = self.python_executable
        result = (runner or self.runner).run(
            command,
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
        *,
        runner: CommandRunner | None = None,
        baseline: StageResult | None = None,
        source: Path | None = None,
    ) -> StageResult:
        started = time.monotonic()
        manifest_result = self._manifest_security_tests(
            sandbox,
            finding,
            runner=runner or self.runner,
            phase="patched",
        )
        dast_result = self._dast_phase(
            source or sandbox,
            sandbox,
            finding,
            phase="patched",
        )
        dynamic_result = self._combine_dynamic_results(
            "exploit_test",
            manifest_result,
            dast_result,
        )
        if dynamic_result is not None and dynamic_result.status is not StageStatus.PASS:
            return dynamic_result

        if finding.cwe in {"CWE-22", "CWE-78", "CWE-502"}:
            return self._python_security_oracle(
                sandbox,
                finding,
                candidate,
                dynamic_result=dynamic_result,
                baseline=baseline,
                started=started,
            )

        if finding.cwe != "CWE-89":
            if dynamic_result is not None:
                return dynamic_result
            return StageResult(
                name="exploit_test",
                status=StageStatus.SKIPPED,
                duration_ms=int((time.monotonic() - started) * 1000),
                reason="no built-in exploit oracle or matching security-test manifest",
            )

        query_variable = str(candidate.metadata.get("query_variable") or "")
        parameters = [str(value) for value in candidate.metadata.get("parameters", [])]
        placeholder = str(candidate.metadata.get("placeholder_style") or "%s")
        if not query_variable or not parameters:
            return StageResult(
                name="exploit_test",
                status=StageStatus.ERROR,
                duration_ms=int((time.monotonic() - started) * 1000),
                reason="candidate lacks structured CWE-89 metadata",
                metadata=self._manifest_metadata(dynamic_result, baseline),
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
            "placeholder": placeholder,
        }
        metadata.update(self._manifest_metadata(dynamic_result, baseline))

        if (
            query_literal is not None
            and placeholder in query_literal
            and all("{" + parameter + "}" not in query_literal for parameter in parameters)
            and safe_execute
        ):
            reason = "attacker-controlled values are structurally separated from SQL syntax"
            if dynamic_result is not None:
                reason = "dynamic security tests and structural SQL oracle passed"
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

    def _python_security_oracle(
        self,
        sandbox: Path,
        finding: Finding,
        candidate: PatchCandidate,
        *,
        dynamic_result: StageResult | None,
        baseline: StageResult | None,
        started: float,
    ) -> StageResult:
        expected_oracles = {
            "CWE-22": "python-ast-flask-safe-directory",
            "CWE-78": "python-ast-subprocess-argv",
            "CWE-502": "python-ast-yaml-safe-load",
        }
        oracle = str(candidate.metadata.get("oracle") or "")
        if oracle != expected_oracles[finding.cwe]:
            return StageResult(
                name="exploit_test",
                status=StageStatus.ERROR,
                duration_ms=int((time.monotonic() - started) * 1000),
                reason=f"candidate lacks structured {finding.cwe} oracle metadata",
                metadata=self._manifest_metadata(dynamic_result, baseline),
            )
        call_line = int(candidate.metadata.get("call_line") or finding.line)
        path = (sandbox / finding.file).resolve()
        path.relative_to(sandbox.resolve())
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=finding.file)
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and node.lineno == call_line
        ]
        confirmed = False
        details: dict[str, Any] = {}

        if finding.cwe == "CWE-78":
            dynamic_arguments = {
                str(value) for value in candidate.metadata.get("dynamic_arguments", [])
            }
            for node in calls:
                call_name = ast.unparse(node.func)
                shell_true = any(
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in node.keywords
                )
                if (
                    call_name
                    not in {"subprocess.run", "subprocess.call", "subprocess.Popen"}
                    or not node.args
                    or not isinstance(node.args[0], ast.List)
                    or not node.args[0].elts
                    or shell_true
                    or not isinstance(node.args[0].elts[0], ast.Constant)
                    or not isinstance(node.args[0].elts[0].value, str)
                ):
                    continue
                argv = [ast.unparse(item) for item in node.args[0].elts]
                confirmed = bool(dynamic_arguments) and dynamic_arguments.issubset(set(argv))
                details = {"argv": argv, "dynamic_arguments": sorted(dynamic_arguments)}
                if confirmed:
                    break

        elif finding.cwe == "CWE-502":
            confirmed = any(
                ast.unparse(node.func) == "yaml.safe_load"
                and len(node.args) == 1
                and not node.keywords
                for node in calls
            )

        elif finding.cwe == "CWE-22":
            root_expression = str(candidate.metadata.get("root_expression") or "")
            path_expression = str(candidate.metadata.get("path_expression") or "")
            for node in calls:
                if ast.unparse(node.func) != "flask.send_from_directory" or len(node.args) < 2:
                    continue
                actual_root = ast.unparse(node.args[0])
                actual_path = ast.unparse(node.args[1])
                confirmed = (
                    bool(root_expression and path_expression)
                    and actual_root == root_expression
                    and actual_path == path_expression
                    and all(ast.unparse(call.func) != "os.path.join" for call in calls)
                )
                details = {
                    "root_expression": actual_root,
                    "path_expression": actual_path,
                }
                if confirmed:
                    break

        metadata: dict[str, Any] = {
            "oracle": oracle,
            "call_line": call_line,
            "confirmed": confirmed,
            **details,
        }
        metadata.update(self._manifest_metadata(dynamic_result, baseline))
        duration = int((time.monotonic() - started) * 1000)
        if confirmed:
            reason = f"{finding.cwe} safe API structure was confirmed"
            if dynamic_result is not None:
                reason = f"dynamic security tests and {finding.cwe} structural oracle passed"
            return StageResult(
                name="exploit_test",
                status=StageStatus.PASS,
                duration_ms=duration,
                reason=reason,
                metadata=metadata,
            )
        return StageResult(
            name="exploit_test",
            status=StageStatus.FAIL,
            duration_ms=duration,
            reason=f"{finding.cwe} safe API structure was not confirmed",
            metadata=metadata,
        )

    def _manifest_security_tests(
        self,
        sandbox: Path,
        finding: Finding,
        *,
        runner: CommandRunner,
        phase: str,
    ) -> StageResult | None:
        if not self.settings.execute_project_security_tests:
            return None
        started = time.monotonic()
        try:
            manifest = load_security_test_manifest(sandbox)
        except ValueError as exc:
            return StageResult(
                name="exploit_baseline" if phase == "baseline" else "exploit_test",
                status=StageStatus.ERROR,
                duration_ms=int((time.monotonic() - started) * 1000),
                reason=str(exc),
            )
        if manifest is None:
            return None

        matching = [
            test
            for test in manifest.tests
            if test.finding in {finding.cwe, finding.finding_id, "*"}
            and (phase == "patched" or test.baseline_expected_exit_code is not None)
        ]
        if not matching:
            return None

        executed: list[dict[str, Any]] = []
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        for entry in matching:
            command = list(entry.command)
            if command[0] in {"python", "python3"}:
                command[0] = self.python_executable
            timeout = min(entry.timeout_seconds, self.settings.exploit_timeout_seconds)
            expected = (
                entry.baseline_expected_exit_code
                if phase == "baseline"
                else entry.expected_exit_code
            )
            if expected is None:
                continue
            result = runner.run(command, cwd=sandbox, timeout_seconds=timeout)
            executed.append(
                {
                    "id": entry.id,
                    "phase": phase,
                    "command": result.argv,
                    "exit_code": result.exit_code,
                    "expected_exit_code": expected,
                    "timed_out": result.timed_out,
                    "duration_ms": result.duration_ms,
                }
            )
            if result.stdout:
                stdout_parts.append(f"[{entry.id}]\n{result.stdout}")
            if result.stderr:
                stderr_parts.append(f"[{entry.id}]\n{result.stderr}")
            if result.timed_out or result.exit_code != expected:
                return StageResult(
                    name="exploit_baseline" if phase == "baseline" else "exploit_test",
                    status=StageStatus.ERROR if result.timed_out else StageStatus.FAIL,
                    command=result.argv,
                    exit_code=result.exit_code,
                    duration_ms=int((time.monotonic() - started) * 1000),
                    stdout_excerpt="\n".join(stdout_parts),
                    stderr_excerpt="\n".join(stderr_parts),
                    reason=(
                        f"security test {entry.id} timed out"
                        if result.timed_out
                        else (
                            f"security test {entry.id} exited {result.exit_code}, "
                            f"expected {expected} during {phase}"
                        )
                    ),
                    metadata={"manifest": "autopatch-security-tests.yaml", "tests": executed},
                )

        return StageResult(
            name="exploit_baseline" if phase == "baseline" else "exploit_test",
            status=StageStatus.PASS,
            duration_ms=int((time.monotonic() - started) * 1000),
            stdout_excerpt="\n".join(stdout_parts),
            stderr_excerpt="\n".join(stderr_parts),
            reason=f"{len(executed)} manifest security test(s) passed during {phase}",
            metadata={"manifest": "autopatch-security-tests.yaml", "tests": executed},
        )

    @staticmethod
    def _combine_dynamic_results(
        name: str,
        *results: StageResult | None,
    ) -> StageResult | None:
        present = [result for result in results if result is not None]
        if not present:
            return None
        status = StageStatus.PASS
        if any(item.status is StageStatus.ERROR for item in present):
            status = StageStatus.ERROR
        elif any(item.status is StageStatus.FAIL for item in present):
            status = StageStatus.FAIL
        elif any(item.status is StageStatus.SKIPPED for item in present):
            status = StageStatus.SKIPPED
        return StageResult(
            name=name,
            status=status,
            duration_ms=sum(item.duration_ms for item in present),
            stdout_excerpt="\n".join(
                item.stdout_excerpt for item in present if item.stdout_excerpt
            ),
            stderr_excerpt="\n".join(
                item.stderr_excerpt for item in present if item.stderr_excerpt
            ),
            reason="; ".join(item.reason for item in present if item.reason) or None,
            metadata={
                "results": [item.model_dump(mode="json") for item in present],
                "manifest_security_tests": [
                    test
                    for item in present
                    for test in item.metadata.get("tests", [])
                ],
                "dast": [
                    report
                    for item in present
                    for report in item.metadata.get("dast", [])
                ],
            },
        )

    @staticmethod
    def _manifest_metadata(
        result: StageResult | None,
        baseline: StageResult | None = None,
    ) -> dict[str, Any]:
        metadata: dict[str, Any] = {}
        if result is not None:
            metadata.update(
                {
                    "manifest_security_tests": result.metadata.get(
                        "manifest_security_tests",
                        result.metadata.get("tests", []),
                    ),
                    "dast": result.metadata.get("dast", []),
                    "dynamic_stdout": result.stdout_excerpt,
                    "dynamic_stderr": result.stderr_excerpt,
                }
            )
        if baseline is not None:
            metadata["baseline"] = baseline.model_dump(mode="json")
        return metadata

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


class DockerSandboxVerifier(LocalCopyVerifier):
    """Verification provider that executes target commands inside hardened containers."""

    name = "docker-sandbox-verifier"
    sandbox_kind = "docker"
    python_executable = "python"

    def __init__(
        self,
        *,
        detection: DetectionService,
        settings: VerificationSettings,
        sandbox_settings: SandboxSettings,
        dast_settings: DastSettings,
        dast_providers: list[DastProvider],
        execute_dast: bool,
        excluded_directories: set[str],
        runner: CommandRunner | None = None,
        applier: SafePatchApplier | None = None,
        application_runner_factory: Callable[..., DockerApplicationRunner] | None = None,
    ) -> None:
        super().__init__(
            detection=detection,
            settings=settings,
            excluded_directories=excluded_directories,
            runner=runner,
            applier=applier,
        )
        self.sandbox_settings = sandbox_settings
        self.dast_settings = dast_settings
        self.execute_dast = execute_dast
        self.dast_providers = {
            provider.name.removesuffix("-dast"): provider for provider in dast_providers
        }
        self.application_runner_factory = (
            application_runner_factory or DockerApplicationRunner
        )

    def _runner_for(self, source: Path, workspace: Path) -> DockerCommandRunner:
        return DockerCommandRunner(
            source=source,
            workspace=workspace,
            settings=self.sandbox_settings,
            runner=self.runner,
        )

    def _copy_target(self, source: Path, destination: Path) -> None:
        super()._copy_target(source, destination)
        prepare_container_workspace(destination)

    def _has_dynamic_dast(self) -> bool:
        return self.execute_dast

    def _dast_phase(
        self,
        source: Path,
        workspace: Path,
        finding: Finding,
        *,
        phase: str,
    ) -> StageResult | None:
        started = time.monotonic()
        try:
            manifest = load_security_test_manifest(workspace)
        except ValueError as exc:
            return StageResult(
                name="exploit_baseline" if phase == "baseline" else "exploit_test",
                status=StageStatus.ERROR,
                reason=str(exc),
            )
        if manifest is None:
            return None
        tests = [
            test
            for test in manifest.dast
            if test.finding in {finding.cwe, finding.finding_id, "*"}
        ]
        if not tests:
            return None
        if not self.execute_dast or not self.dast_settings.enabled:
            return StageResult(
                name="exploit_baseline" if phase == "baseline" else "exploit_test",
                status=StageStatus.ERROR,
                reason="manifest requests DAST but the explicit DAST gate is disabled",
            )
        if manifest.application is None:
            return StageResult(
                name="exploit_baseline" if phase == "baseline" else "exploit_test",
                status=StageStatus.ERROR,
                reason="manifest DAST tests require an application specification",
            )

        evidence: list[dict[str, Any]] = []
        try:
            launcher = self.application_runner_factory(
                source=source,
                workspace=workspace,
                settings=self.sandbox_settings,
                runner=self.runner,
            )
            with launcher.start(manifest.application) as application:
                for test in tests:
                    provider = self.dast_providers.get(test.tool)
                    if provider is None:
                        raise RuntimeError(f"DAST provider is not enabled: {test.tool}")
                    if not provider.available():
                        raise RuntimeError(f"DAST provider is unavailable: {test.tool}")
                    target = application.target + (
                        "" if test.path == "/" else test.path
                    )
                    report = provider.scan(
                        target,
                        sandbox_target=True,
                        network_name=application.network_name,
                        workspace=workspace,
                        template=test.template,
                    )
                    count = len(report.findings)
                    expected = (
                        count >= test.baseline_min_findings
                        if phase == "baseline"
                        else count <= test.patched_max_findings
                    )
                    evidence.append(
                        {
                            "id": test.id,
                            "phase": phase,
                            "finding_count": count,
                            "baseline_min_findings": test.baseline_min_findings,
                            "patched_max_findings": test.patched_max_findings,
                            "scan": report.model_dump(mode="json"),
                        }
                    )
                    if report.status is not StageStatus.PASS:
                        return StageResult(
                            name=(
                                "exploit_baseline" if phase == "baseline" else "exploit_test"
                            ),
                            status=StageStatus.ERROR,
                            duration_ms=int((time.monotonic() - started) * 1000),
                            reason=f"{test.tool} scan failed: {report.reason}",
                            metadata={"dast": evidence},
                        )
                    if not expected:
                        relation = (
                            f">= {test.baseline_min_findings}"
                            if phase == "baseline"
                            else f"<= {test.patched_max_findings}"
                        )
                        return StageResult(
                            name=(
                                "exploit_baseline" if phase == "baseline" else "exploit_test"
                            ),
                            status=StageStatus.FAIL,
                            duration_ms=int((time.monotonic() - started) * 1000),
                            reason=(
                                f"DAST test {test.id} found {count}; expected {relation} "
                                f"during {phase}"
                            ),
                            metadata={"dast": evidence},
                        )
        except Exception as exc:
            return StageResult(
                name="exploit_baseline" if phase == "baseline" else "exploit_test",
                status=StageStatus.ERROR,
                duration_ms=int((time.monotonic() - started) * 1000),
                reason=f"dynamic application/DAST failed: {type(exc).__name__}: {exc}",
                metadata={"dast": evidence},
            )

        return StageResult(
            name="exploit_baseline" if phase == "baseline" else "exploit_test",
            status=StageStatus.PASS,
            duration_ms=int((time.monotonic() - started) * 1000),
            reason=f"{len(evidence)} DAST differential expectation(s) passed during {phase}",
            metadata={"dast": evidence},
        )
