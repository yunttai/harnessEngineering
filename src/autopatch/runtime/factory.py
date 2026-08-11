from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from autopatch.config import HarnessSettings
from autopatch.repo import ArtifactStore
from autopatch.runtime.builtin_patcher import BuiltinCwe89Patcher
from autopatch.runtime.builtin_scanner import BuiltinPythonScanner
from autopatch.runtime.external_scanners import GitleaksScanner, TrivyScanner
from autopatch.runtime.git_publisher import LocalGitPublisher
from autopatch.runtime.github_publisher import GitHubAppPullRequestPublisher
from autopatch.runtime.openai_provider import OpenAIResponsesProvider
from autopatch.runtime.patch_apply import SafePatchApplier
from autopatch.runtime.semgrep_scanner import SemgrepScanner
from autopatch.runtime.verifier import LocalCopyVerifier
from autopatch.service.analysis import RuleBasedAnalyzer
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
) -> Orchestrator:
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
            )
            # Keep auto/explicit providers in the registry even when unavailable so
            # DetectionService records the skipped tool as execution evidence.
            scanners.append(semgrep)
        elif scanner_config.name == "trivy":
            scanners.append(
                TrivyScanner(
                    required=scanner_config.required,
                    timeout_seconds=scanner_config.timeout_seconds,
                )
            )
        elif scanner_config.name == "gitleaks":
            scanners.append(
                GitleaksScanner(
                    required=scanner_config.required,
                    timeout_seconds=scanner_config.timeout_seconds,
                )
            )

    detection = DetectionService(
        scanners,
        fail_on_required_error=settings.detection.fail_on_required_scanner_error,
    )

    verification_settings = deepcopy(settings.verification)
    if execute_tests is not None:
        verification_settings.execute_project_tests = execute_tests
    if execute_security_tests is not None:
        verification_settings.execute_project_security_tests = execute_security_tests

    applier = SafePatchApplier()
    verifier = LocalCopyVerifier(
        detection=detection,
        settings=verification_settings,
        excluded_directories=excluded,
        applier=applier,
    )
    artifact_root = Path(settings.artifact_root)
    if not artifact_root.is_absolute():
        artifact_root = Path.cwd() / artifact_root
    store = ArtifactStore(
        artifact_root,
        redact_patterns=settings.logging.redact_patterns,
    )

    analyzer = RuleBasedAnalyzer()
    patch_providers = [BuiltinCwe89Patcher()]
    if settings.llm.enabled:
        llm = OpenAIResponsesProvider(settings.llm)
        if not llm.available():
            raise RuntimeError(
                f"llm.enabled requires credential environment variable {settings.llm.api_key_env}"
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
