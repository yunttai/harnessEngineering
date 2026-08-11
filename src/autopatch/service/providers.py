from __future__ import annotations

from pathlib import Path

from autopatch.providers import PatchProvider
from autopatch.types import AnalysisResult, Finding, PatchCandidate, PatchFeedback


class CompositePatchProvider:
    """Collect candidates from independent providers without hiding total failure."""

    name = "composite-patch-provider"

    def __init__(self, providers: list[PatchProvider]) -> None:
        if not providers:
            raise ValueError("at least one patch provider is required")
        self.providers = providers

    def generate(
        self,
        target: Path,
        finding: Finding,
        analysis: AnalysisResult,
        feedback: list[PatchFeedback] | None = None,
    ) -> list[PatchCandidate]:
        unique: dict[str, PatchCandidate] = {}
        errors: list[str] = []
        for provider in self.providers:
            try:
                candidates = provider.generate(target, finding, analysis, feedback)
            except Exception as exc:
                errors.append(f"{provider.name}: {type(exc).__name__}: {exc}")
                continue
            for candidate in candidates:
                unique.setdefault(candidate.candidate_id, candidate)
        if not unique and errors:
            raise RuntimeError("; ".join(errors))
        return list(unique.values())
