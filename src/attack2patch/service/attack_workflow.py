import hashlib
import shutil
from pathlib import Path
from uuid import UUID

from attack2patch.config.settings import Settings
from attack2patch.repo.sqlite_repository import SQLiteRepository
from attack2patch.service.attack_detector import inspect_sql_injection
from attack2patch.service.code_scanner import scan_function
from attack2patch.service.patch_generator import generate_parameterized_query_patch
from attack2patch.service.route_mapper import ensure_repository_path, map_flask_route
from attack2patch.service.validation_service import CandidateValidator, ValidationResult
from attack2patch.service.workspace_integrity import workspace_digest
from attack2patch.types.attack_event import AttackEvent, EventStatus
from attack2patch.types.finding import CodeFinding
from attack2patch.types.http_log import HttpLogRecord
from attack2patch.types.patch import PatchCandidate, PatchStatus


class WorkflowError(RuntimeError):
    pass


class AttackWorkflowService:
    def __init__(
        self,
        settings: Settings,
        repository: SQLiteRepository,
        validator: CandidateValidator,
    ) -> None:
        self.settings = settings
        self.repository = repository
        self.validator = validator

    def analyze(self, record: HttpLogRecord) -> AttackEvent | None:
        matches = [
            match
            for value in record.detection_values()
            for match in inspect_sql_injection(value)
        ]
        if not matches:
            return None
        event = AttackEvent(
            detected_at=record.timestamp,
            source_ip=record.source_ip,
            method=record.method,
            path=record.path,
            sanitized_payload=record.sanitized_payload(),
            evidence={
                "rule_ids": sorted({match.rule_id for match in matches}),
                "matched_text": sorted({match.matched_text for match in matches}),
            },
        )
        self.repository.save_event(event)
        try:
            route = map_flask_route(
                self.settings.repository_root,
                self.settings.demo_app_root,
                record.path,
            )
            source_path = ensure_repository_path(
                self.settings.repository_root, Path(route.file_path)
            )
            code_matches = scan_function(source_path, route.function_name)
            if not code_matches:
                raise LookupError("route has no supported vulnerable SQL pattern")
            code_match = code_matches[0]
            finding = CodeFinding(
                event_id=event.id,
                file_path=route.file_path,
                function_name=route.function_name,
                line_number=code_match.line_number,
                rule_id=code_match.rule_id,
                vulnerable_code=code_match.vulnerable_code,
            )
            self.repository.save_finding(finding)
            event.status = EventStatus.CODE_LOCATED
        except (LookupError, OSError, SyntaxError, ValueError) as exc:
            event.status = EventStatus.FAILED
            event.error = f"code mapping failed: {exc}"
        self.repository.save_event(event)
        return event

    def generate_patch(self, event_id: str | UUID) -> PatchCandidate:
        event = self._require_event(event_id)
        if event.status != EventStatus.CODE_LOCATED:
            raise WorkflowError(f"event is not patchable from status {event.status.value}")
        findings = self.repository.findings_for_event(event.id)
        if len(findings) != 1:
            raise WorkflowError("MVP requires exactly one code finding")
        finding = findings[0]
        source_path = ensure_repository_path(
            self.settings.repository_root, Path(finding.file_path)
        )
        source = source_path.read_text(encoding="utf-8")
        generated = generate_parameterized_query_patch(source, finding.file_path)
        patch = PatchCandidate(
            finding_id=finding.id,
            file_path=finding.file_path,
            diff=generated.diff,
            reason=generated.reason,
            before_sha256=hashlib.sha256(source.encode()).hexdigest(),
        )
        self.repository.save_patch(patch)
        event.status = EventStatus.REVIEW_REQUIRED
        self.repository.save_event(event)
        return patch

    def approve_patch(self, patch_id: str | UUID) -> PatchCandidate:
        patch = self._require_patch(patch_id)
        if patch.status != PatchStatus.GENERATED:
            raise WorkflowError(f"patch cannot be approved from status {patch.status.value}")
        source_path = ensure_repository_path(
            self.settings.repository_root, Path(patch.file_path)
        )
        source = source_path.read_text(encoding="utf-8")
        if hashlib.sha256(source.encode()).hexdigest() != patch.before_sha256:
            raise WorkflowError("source changed after patch generation")

        workspace = self.settings.resolved_workspace / str(patch.id)
        candidate_root = workspace / self.settings.demo_app_path
        workspace.mkdir(parents=True, exist_ok=False)
        shutil.copytree(self.settings.demo_app_root, candidate_root, symlinks=True)
        candidate_file = ensure_repository_path(workspace, Path(patch.file_path))
        if candidate_file.is_symlink() or not candidate_file.is_file():
            raise WorkflowError("candidate target must be a regular file")
        generated = generate_parameterized_query_patch(source, patch.file_path)
        if generated.diff != patch.diff:
            raise WorkflowError("generated patch no longer matches approved diff")
        temporary_file = candidate_file.with_suffix(candidate_file.suffix + ".tmp")
        temporary_file.write_text(generated.after, encoding="utf-8")
        temporary_file.replace(candidate_file)

        patch.status = PatchStatus.APPROVED
        patch.workspace_path = str(workspace)
        self.repository.save_patch(patch)
        return patch

    def reject_patch(self, patch_id: str | UUID) -> PatchCandidate:
        patch = self._require_patch(patch_id)
        if patch.status != PatchStatus.GENERATED:
            raise WorkflowError(f"patch cannot be rejected from status {patch.status.value}")
        patch.status = PatchStatus.REJECTED
        self.repository.save_patch(patch)
        return patch

    def validate_patch(self, patch_id: str | UUID) -> tuple[PatchCandidate, ValidationResult]:
        patch = self._require_patch(patch_id)
        if patch.status != PatchStatus.APPROVED or not patch.workspace_path:
            raise WorkflowError("only an approved patch in an isolated workspace can be validated")
        workspace = self._ensure_workspace_path(Path(patch.workspace_path))
        candidate_file = ensure_repository_path(workspace, Path(patch.file_path))
        result = self.validator(workspace, candidate_file)
        patch.validation_result = result.as_dict()
        event = self._event_for_patch(patch)
        if result.deployable:
            patch.status = PatchStatus.VALIDATED
            patch.validated_sha256 = workspace_digest(workspace)
            event.status = EventStatus.TEST_PASSED
        else:
            patch.status = PatchStatus.VALIDATION_FAILED
            event.status = EventStatus.FAILED
            event.error = "candidate patch failed one or more validation gates"
        self.repository.save_patch(patch)
        self.repository.save_event(event)
        return patch, result

    def event_details(self, event_id: str | UUID) -> dict[str, object]:
        event = self._require_event(event_id)
        findings = self.repository.findings_for_event(event.id)
        patches = self.repository.patches_for_event(event.id)
        deployments = [
            deployment
            for patch in patches
            for deployment in self.repository.deployments_for_patch(patch.id)
        ]
        return {
            "event": event,
            "findings": findings,
            "patches": patches,
            "deployments": deployments,
            "transitions": self.repository.transitions_for_event(event.id),
        }

    def _require_event(self, event_id: str | UUID) -> AttackEvent:
        event = self.repository.get(event_id)
        if not event:
            raise LookupError("attack event not found")
        return event

    def _require_patch(self, patch_id: str | UUID) -> PatchCandidate:
        patch = self.repository.get_patch(patch_id)
        if not patch:
            raise LookupError("patch candidate not found")
        return patch

    def _event_for_patch(self, patch: PatchCandidate) -> AttackEvent:
        finding = self.repository.get_finding(patch.finding_id)
        if not finding:
            raise WorkflowError("patch finding is missing")
        return self._require_event(finding.event_id)

    def _ensure_workspace_path(self, candidate: Path) -> Path:
        root = self.settings.resolved_workspace
        resolved = candidate.resolve()
        if root not in resolved.parents:
            raise WorkflowError("candidate workspace escapes configured workspace")
        return resolved
