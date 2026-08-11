from __future__ import annotations

import difflib
import hashlib
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any, Protocol

import httpx
from pydantic import BaseModel, ConfigDict

from autopatch.config import LlmSettings
from autopatch.runtime.fs import ensure_within, sha256_file
from autopatch.runtime.patch_apply import apply_edits_to_text
from autopatch.service.normalization import normalize_relative_path
from autopatch.types import (
    AnalysisResult,
    CodeContext,
    Exploitability,
    Finding,
    PatchCandidate,
    PatchFeedback,
    TextEdit,
)


class _ResponseLike(Protocol):
    status_code: int

    def json(self) -> Any: ...


class _HttpClient(Protocol):
    def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        json: dict[str, Any],
    ) -> _ResponseLike: ...


class _AnalysisOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root_cause: str
    exploitability: Exploitability
    confidence: float
    source: str
    sink: str
    existing_validation: list[str]
    recommended_fix: str
    forbidden_fixes: list[str]
    required_tests: list[str]
    notes: list[str]


class _EditOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file: str
    start_line: int
    end_line: int
    replacement: str


class _CandidateOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str
    description: str
    rationale: str
    expected_security_effect: str
    edits: list[_EditOutput]


class _PatchOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidates: list[_CandidateOutput]


class OpenAIResponsesProvider:
    """OpenAI Responses API provider with strict JSON Schema output validation.

    Network use is opt-in through ``llm.enabled``. API credentials are read only
    from the configured environment variable and are never included in evidence.
    """

    name = "openai-responses"

    def __init__(
        self,
        settings: LlmSettings,
        *,
        client: _HttpClient | None = None,
    ) -> None:
        self.settings = settings
        self._client = client

    def available(self) -> bool:
        return bool(os.getenv(self.settings.api_key_env))

    def analyze(self, target: Path, finding: Finding) -> AnalysisResult:
        target = target.resolve()
        context = self._context(target, finding)
        raw, response_id = self._structured_request(
            schema_name="attack2patch_analysis",
            schema=_AnalysisOutput.model_json_schema(),
            system=(
                "Analyze an authorized local source-code security finding. Return only the "
                "requested structured result. Distinguish scanner facts from inference, never "
                "claim verification, and recommend the smallest secure coding fix. Use an empty "
                "string when source or sink is unknown."
            ),
            user=json.dumps(
                {
                    "finding": finding.model_dump(mode="json"),
                    "code_context": context.model_dump(mode="json"),
                },
                ensure_ascii=False,
            ),
        )
        output = _AnalysisOutput.model_validate(raw)
        if not 0.0 <= output.confidence <= 1.0:
            raise ValueError("LLM analysis confidence must be between 0 and 1")
        return AnalysisResult(
            finding_id=finding.finding_id,
            cwe=finding.cwe,
            root_cause=output.root_cause,
            exploitability=output.exploitability,
            confidence=output.confidence,
            source=output.source or None,
            sink=output.sink or None,
            existing_validation=output.existing_validation,
            recommended_fix=output.recommended_fix,
            forbidden_fixes=output.forbidden_fixes,
            required_tests=output.required_tests,
            context=context,
            notes=[*output.notes, f"provider_response_id={response_id}"],
        )

    def generate(
        self,
        target: Path,
        finding: Finding,
        analysis: AnalysisResult,
        feedback: list[PatchFeedback] | None = None,
    ) -> list[PatchCandidate]:
        target = target.resolve()
        raw, response_id = self._structured_request(
            schema_name="attack2patch_patch_candidates",
            schema=_PatchOutput.model_json_schema(),
            system=(
                "Generate minimal security patch candidates for an authorized local repository. "
                "Return exact 1-based inclusive TextEdit ranges and replacement text. Do not add "
                "scanner suppressions, weaken tests, change unrelated formatting, add secrets, or "
                "claim a patch is verified. Return an empty candidates array when a safe minimal "
                "edit is not justified."
            ),
            user=json.dumps(
                {
                    "finding": finding.model_dump(mode="json"),
                    "analysis": analysis.model_dump(mode="json"),
                    "verification_feedback": [
                        item.model_dump(mode="json") for item in (feedback or [])
                    ],
                },
                ensure_ascii=False,
            ),
        )
        output = _PatchOutput.model_validate(raw)
        candidates: list[PatchCandidate] = []
        for item in output.candidates:
            candidates.append(
                self._materialize_candidate(
                    target,
                    finding,
                    item,
                    response_id=response_id,
                )
            )
        return candidates

    def _structured_request(
        self,
        *,
        schema_name: str,
        schema: dict[str, Any],
        system: str,
        user: str,
    ) -> tuple[dict[str, Any], str]:
        api_key = os.getenv(self.settings.api_key_env)
        if not api_key:
            raise RuntimeError(f"missing LLM credential environment variable: {self.settings.api_key_env}")
        payload = {
            "model": self.settings.model,
            "input": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_output_tokens": self.settings.max_output_tokens,
            "store": False,
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": schema_name,
                    "strict": True,
                    "schema": schema,
                }
            },
        }
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        url = f"{self.settings.base_url}/responses"
        try:
            if self._client is None:
                with httpx.Client(timeout=self.settings.timeout_seconds) as client:
                    response = client.post(url, headers=headers, json=payload)
            else:
                response = self._client.post(url, headers=headers, json=payload)
        except httpx.HTTPError as exc:
            raise RuntimeError(f"OpenAI Responses request failed: {type(exc).__name__}") from exc

        if response.status_code < 200 or response.status_code >= 300:
            raise RuntimeError(f"OpenAI Responses request returned HTTP {response.status_code}")
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("OpenAI Responses payload must be an object")
        response_id = str(data.get("id") or "unknown")
        if data.get("status") != "completed":
            detail = data.get("incomplete_details") or {}
            reason = detail.get("reason") if isinstance(detail, dict) else None
            raise RuntimeError(f"OpenAI Responses request incomplete: {reason or data.get('status')}")

        output_text: str | None = None
        for item in data.get("output") or []:
            if not isinstance(item, dict) or item.get("type") != "message":
                continue
            for content in item.get("content") or []:
                if not isinstance(content, dict):
                    continue
                if content.get("type") == "refusal":
                    raise RuntimeError("OpenAI Responses request was refused")
                if content.get("type") == "output_text":
                    output_text = str(content.get("text") or "")
        if output_text is None:
            raise ValueError("OpenAI Responses payload contained no output_text")
        parsed = json.loads(output_text)
        if not isinstance(parsed, dict):
            raise ValueError("structured output root must be an object")
        return parsed, response_id

    @staticmethod
    def _context(target: Path, finding: Finding, radius: int = 8) -> CodeContext:
        path = ensure_within(target, target / finding.file)
        lines = path.read_text(encoding="utf-8").splitlines()
        start = max(1, finding.line - radius)
        end = min(len(lines), (finding.end_line or finding.line) + radius)
        snippet = "\n".join(
            f"{line_number:>5}: {lines[line_number - 1]}"
            for line_number in range(start, end + 1)
        )
        return CodeContext(
            file=finding.file,
            start_line=start,
            end_line=end,
            snippet=snippet,
            function=finding.function,
        )

    def _materialize_candidate(
        self,
        target: Path,
        finding: Finding,
        item: _CandidateOutput,
        *,
        response_id: str,
    ) -> PatchCandidate:
        if not item.edits:
            raise ValueError("LLM candidate must contain at least one TextEdit")
        edits: list[TextEdit] = []
        grouped: dict[str, list[TextEdit]] = defaultdict(list)
        forbidden_markers = ("nosemgrep", "noqa", "scanner-ignore", "pragma: allowlist")
        for raw in item.edits:
            relative = normalize_relative_path(raw.file)
            path = ensure_within(target, target / relative)
            if not path.is_file():
                raise FileNotFoundError(path)
            source_lines = path.read_text(encoding="utf-8").splitlines()
            if raw.start_line < 1 or raw.end_line < raw.start_line:
                raise ValueError("invalid LLM TextEdit range")
            if raw.end_line > len(source_lines):
                raise ValueError("LLM TextEdit exceeds source length")
            lowered = raw.replacement.lower()
            if any(marker in lowered for marker in forbidden_markers):
                raise ValueError("LLM candidate contains a forbidden scanner suppression")
            edit = TextEdit(
                file=relative,
                start_line=raw.start_line,
                end_line=raw.end_line,
                replacement=raw.replacement,
                original_sha256=sha256_file(path),
            )
            edits.append(edit)
            grouped[relative].append(edit)

        diff_parts: list[str] = []
        changed_lines = 0
        for relative in sorted(grouped):
            path = ensure_within(target, target / relative)
            source = path.read_text(encoding="utf-8")
            patched = apply_edits_to_text(source, grouped[relative])
            diff_parts.extend(
                difflib.unified_diff(
                    source.splitlines(keepends=True),
                    patched.splitlines(keepends=True),
                    fromfile=f"a/{relative}",
                    tofile=f"b/{relative}",
                )
            )
            changed_lines += sum(
                (edit.end_line - edit.start_line + 1)
                + max(1, len(edit.replacement.splitlines()))
                for edit in grouped[relative]
            )
        diff = "".join(diff_parts)
        digest = hashlib.sha256(f"{finding.finding_id}\n{diff}".encode("utf-8")).hexdigest()
        return PatchCandidate(
            candidate_id=f"PATCH-{digest[:12].upper()}",
            finding_id=finding.finding_id,
            title=item.title,
            description=item.description,
            rationale=item.rationale,
            expected_security_effect=item.expected_security_effect,
            edits=edits,
            unified_diff=diff,
            changed_files=sorted(grouped),
            changed_lines=changed_lines,
            provider=self.name,
            metadata={"provider_response_id": response_id},
        )
