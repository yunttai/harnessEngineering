from __future__ import annotations

import shutil
from copy import deepcopy
from pathlib import Path

from autopatch.config import HarnessSettings
from autopatch.providers import DastProvider
from autopatch.repo import ArtifactStore
from autopatch.runtime.builtin_patcher import BuiltinCwe89Patcher
from autopatch.runtime.builtin_scanner import BuiltinPythonScanner
from autopatch.runtime.builtin_security_patchers import (
    BuiltinCwe22FlaskPatcher,
    BuiltinCwe78Patcher,
    BuiltinCwe502YamlPatcher,
)
from autopatch.runtime.cli_llm_provider import CliLlmProvider
from autopatch.runtime.dast import NucleiDastProvider, ZapDastProvider
from autopatch.runtime.deployment import CommandDeploymentProvider
from autopatch.runtime.external_scanners import GitleaksScanner, TrivyScanner
from autopatch.runtime.git_publisher import LocalGitPublisher
from autopatch.runtime.github_publisher import GitHubAppPullRequestPublisher
from autopatch.runtime.patch_apply import SafePatchApplier
from autopatch.runtime.semgrep_scanner import SemgrepScanner
from autopatch.runtime.verifier import DockerSandboxVerifier, LocalCopyVerifier
from autopatch.service.analysis import RuleBasedAnalyzer
from autopatch.service.dast import DastService
from autopatch.service.deployment import DeploymentService
from autopatch.service.detection import DetectionService
from autopatch.service.orchestrator import Orchestrator
from autopatch.service.providers import CompositePatchProvider
from autopatch.service.publishing import PublishingService


def build_orchestrator(
    *,
    settings: HarnessSettings,
    config_path: Path,
    execute_tests: bool | None = None,
    execute_security_tests: bool | None = None,
    execute_dast: bool | None = None,
) -> Orchestrator:
    detection = build_detection_service(settings=settings, config_path=config_path)
    excluded = set(settings.scope.excluded_directories)

    verification_settings = deepcopy(settings.verification)
    if execute_tests is not None:
        verification_settings.execute_project_tests = execute_tests
    if execute_security_tests is not None:
        verification_settings.execute_project_security_tests = execute_security_tests

    applier = SafePatchApplier()
    run_dast = bool(execute_dast)
    if run_dast and (
        not settings.autonomy.execute_dast or not settings.dast.enabled
    ):
        raise PermissionError(
            "DAST execution requires autonomy.execute_dast=true and dast.enabled=true"
        )
    dast_providers = build_dast_providers(settings=settings)
    if settings.sandbox.provider == "docker":
        if shutil.which(settings.sandbox.docker_executable) is None:
            raise RuntimeError(
                f"Docker sandbox executable is unavailable: {settings.sandbox.docker_executable}"
            )
        verifier = DockerSandboxVerifier(
            detection=detection,
            settings=verification_settings,
            sandbox_settings=settings.sandbox,
            dast_settings=settings.dast,
            dast_providers=dast_providers,
            execute_dast=run_dast,
            excluded_directories=excluded,
            applier=applier,
        )
    else:
        if run_dast:
            raise ValueError("dynamic DAST verification requires sandbox.provider=docker")
        verifier = LocalCopyVerifier(
            detection=detection,
            settings=verification_settings,
            excluded_directories=excluded,
            applier=applier,
        )
    store = build_artifact_store(settings=settings)

    analyzer = RuleBasedAnalyzer()
    patch_providers = [
        BuiltinCwe89Patcher(),
        BuiltinCwe22FlaskPatcher(),
        BuiltinCwe78Patcher(),
        BuiltinCwe502YamlPatcher(),
    ]
    if settings.llm.enabled:
        llm = CliLlmProvider(settings.llm)
        if not llm.available():
            raise RuntimeError(
                f"llm.enabled requires installed CLI executable: {llm.executable_name}"
            )
        if settings.llm.use_for_analysis:
            analyzer = llm
        if settings.llm.use_for_patching:
            patch_providers.append(llm)

    patcher = (
        patch_providers[0]
        if len(patch_providers) == 1
        else CompositePatchProvider(patch_providers)
    )

    return Orchestrator(
        settings=settings,
        config_path=config_path,
        detection=detection,
        analyzer=analyzer,
        patcher=patcher,
        verifier=verifier,
        applier=applier,
        store=store,
    )


def build_detection_service(
    *,
    settings: HarnessSettings,
    config_path: Path,
) -> DetectionService:
    config_path = config_path.resolve()
    excluded = set(settings.scope.excluded_directories)
    scanners = []
    repository_root = config_path.parent.parent

    for scanner_config in settings.detection.scanners:
        if scanner_config.enabled is False:
            continue
        if scanner_config.name == "builtin-python":
            scanners.append(
                BuiltinPythonScanner(
                    required=scanner_config.required,
                    excluded_directories=excluded,
                    max_file_bytes=settings.scope.max_file_bytes,
                )
            )
        elif scanner_config.name == "semgrep":
            rules = Path(scanner_config.config or "rules/semgrep")
            if not rules.is_absolute():
                rules = repository_root / rules
            semgrep = SemgrepScanner(
                config_path=rules,
                required=scanner_config.required,
                timeout_seconds=scanner_config.timeout_seconds,
                execution=scanner_config.execution,
                docker_image=scanner_config.docker_image,
                docker_network=scanner_config.docker_network,
                sandbox_settings=settings.sandbox,
            )
            # Keep auto/explicit providers in the registry even when unavailable so
            # DetectionService records the skipped tool as execution evidence.
            scanners.append(semgrep)
        elif scanner_config.name == "trivy":
            scanners.append(
                TrivyScanner(
                    required=scanner_config.required,
                    timeout_seconds=scanner_config.timeout_seconds,
                    execution=scanner_config.execution,
                    docker_image=scanner_config.docker_image,
                    docker_network=scanner_config.docker_network,
                    cache_dir=Path.cwd() / ".autopatch" / "cache" / "trivy",
                    sandbox_settings=settings.sandbox,
                )
            )
        elif scanner_config.name == "gitleaks":
            scanners.append(
                GitleaksScanner(
                    required=scanner_config.required,
                    timeout_seconds=scanner_config.timeout_seconds,
                    execution=scanner_config.execution,
                    docker_image=scanner_config.docker_image,
                    docker_network=scanner_config.docker_network,
                    sandbox_settings=settings.sandbox,
                )
            )

    return DetectionService(
        scanners,
        fail_on_required_error=settings.detection.fail_on_required_scanner_error,
    )


def build_artifact_store(*, settings: HarnessSettings) -> ArtifactStore:
    artifact_root = Path(settings.artifact_root)
    if not artifact_root.is_absolute():
        artifact_root = Path.cwd() / artifact_root
    return ArtifactStore(
        artifact_root,
        redact_patterns=settings.logging.redact_patterns,
    )


def build_publishing_service(
    *,
    settings: HarnessSettings,
) -> PublishingService:
    pull_requests = None
    if settings.publishing.github_app.enabled:
        pull_requests = GitHubAppPullRequestPublisher(settings.publishing.github_app)
    return PublishingService(
        settings=settings,
        git=LocalGitPublisher(),
        applier=SafePatchApplier(),
        pull_requests=pull_requests,
    )


def build_dast_providers(*, settings: HarnessSettings) -> list[DastProvider]:
    providers: list[DastProvider] = []
    if settings.dast.zap.enabled:
        providers.append(
            ZapDastProvider(
                settings.dast,
                settings.dast.zap,
                sandbox_settings=settings.sandbox,
            )
        )
    if settings.dast.nuclei.enabled:
        providers.append(
            NucleiDastProvider(
                settings.dast,
                settings.dast.nuclei,
                sandbox_settings=settings.sandbox,
            )
        )
    return providers


def build_dast_service(*, settings: HarnessSettings) -> DastService:
    return DastService(build_dast_providers(settings=settings))


def build_deployment_service(
    *,
    settings: HarnessSettings,
    config_path: Path,
) -> DeploymentService:
    repository_root = config_path.resolve().parent.parent
    provider = CommandDeploymentProvider(
        settings.deployment,
        repository_root=repository_root,
    )
    return DeploymentService(settings=settings, provider=provider)
