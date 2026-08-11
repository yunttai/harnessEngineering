from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from autopatch.types import (
    AnalysisResult,
    CandidateEvaluation,
    Finding,
    PatchCandidate,
    PatchFeedback,
    RunReport,
)

_DEFAULT_REDACTORS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[0-9A-Za-z]{36}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.DOTALL),
)


class ArtifactStore:
    """File-based evidence store with best-effort secret redaction for the MVP."""

    def __init__(self, root: Path, redact_patterns: list[str] | None = None) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._redactors = list(_DEFAULT_REDACTORS)
        for pattern in redact_patterns or []:
            try:
                self._redactors.append(re.compile(pattern))
            except re.error as exc:
                raise ValueError(f"invalid logging.redact_patterns entry {pattern!r}: {exc}") from exc

    def run_dir(self, run_id: str) -> Path:
        safe = "".join(ch for ch in run_id if ch.isalnum() or ch in "-_")
        if not safe:
            raise ValueError("invalid run id")
        path = (self.root / safe).resolve()
        path.relative_to(self.root)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def write_json(self, path: Path, value: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(value, BaseModel):
            payload: Any = value.model_dump(mode="json")
        elif isinstance(value, list):
            payload = [
                item.model_dump(mode="json") if isinstance(item, BaseModel) else item
                for item in value
            ]
        else:
            payload = value
        payload = self._redact_value(payload)
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def write_findings(self, run_id: str, findings: list[Finding]) -> None:
        self.write_json(self.run_dir(run_id) / "findings.json", findings)

    def write_analysis(self, run_id: str, finding_id: str, analysis: AnalysisResult) -> None:
        self.write_json(self._finding_dir(run_id, finding_id) / "analysis.json", analysis)

    def write_candidates(
        self,
        run_id: str,
        finding_id: str,
        candidates: list[PatchCandidate],
    ) -> None:
        self.write_json(self._finding_dir(run_id, finding_id) / "candidates.json", candidates)

    def write_evaluations(
        self,
        run_id: str,
        finding_id: str,
        evaluations: list[CandidateEvaluation],
    ) -> None:
        self.write_json(self._finding_dir(run_id, finding_id) / "evaluations.json", evaluations)

    def write_feedback(
        self,
        run_id: str,
        finding_id: str,
        feedback: list[PatchFeedback],
    ) -> None:
        self.write_json(self._finding_dir(run_id, finding_id) / "feedback.json", feedback)

    def write_selected_diff(self, run_id: str, finding_id: str, diff: str) -> None:
        path = self._finding_dir(run_id, finding_id) / "selected.diff"
        path.write_text(self._redact_text(diff), encoding="utf-8")

    def write_run(self, report: RunReport) -> Path:
        run_dir = self.run_dir(report.run_id)
        self.write_json(run_dir / "run.json", report)
        events = "\n".join(
            json.dumps(
                self._redact_value(event.model_dump(mode="json")),
                ensure_ascii=False,
                sort_keys=True,
            )
            for event in report.events
        )
        (run_dir / "events.jsonl").write_text(
            events + ("\n" if events else ""),
            encoding="utf-8",
        )
        return run_dir

    def read_run(self, run_id: str) -> RunReport:
        safe = "".join(ch for ch in run_id if ch.isalnum() or ch in "-_")
        if safe != run_id or not safe:
            raise ValueError("invalid run id")
        path = (self.root / safe / "run.json").resolve()
        path.relative_to(self.root)
        if not path.is_file():
            raise FileNotFoundError(path)
        return RunReport.model_validate_json(path.read_text(encoding="utf-8"))

    def _finding_dir(self, run_id: str, finding_id: str) -> Path:
        safe = "".join(ch for ch in finding_id if ch.isalnum() or ch in "-_")
        path = (self.run_dir(run_id) / f"finding-{safe}").resolve()
        path.relative_to(self.run_dir(run_id))
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _redact_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._redact_text(value)
        if isinstance(value, list):
            return [self._redact_value(item) for item in value]
        if isinstance(value, tuple):
            return [self._redact_value(item) for item in value]
        if isinstance(value, dict):
            return {str(key): self._redact_value(item) for key, item in value.items()}
        return value

    def _redact_text(self, value: str) -> str:
        redacted = value
        for pattern in self._redactors:
            redacted = pattern.sub("<redacted>", redacted)
        return redacted
