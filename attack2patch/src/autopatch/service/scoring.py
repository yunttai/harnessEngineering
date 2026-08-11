from __future__ import annotations

from autopatch.types import PatchCandidate, PatchScore, StageResult, StageStatus


def _security_points(rescan: StageResult, exploit: StageResult) -> int:
    if rescan.status is not StageStatus.PASS:
        return 0
    if exploit.status is StageStatus.FAIL or exploit.status is StageStatus.ERROR:
        return 0
    if exploit.status is StageStatus.PASS:
        return 40
    return 30


def _regression_points(functional: StageResult) -> int:
    if functional.status is StageStatus.PASS:
        return 30
    if functional.status is StageStatus.SKIPPED:
        return 15
    return 0


def _change_size_points(candidate: PatchCandidate) -> int:
    changed = candidate.changed_lines
    if changed <= 5:
        return 15
    if changed <= 15:
        return 12
    if changed <= 30:
        return 8
    if changed <= 80:
        return 4
    return 0


def _style_points(candidate: PatchCandidate) -> int:
    replacements = "\n".join(edit.replacement for edit in candidate.edits)
    if "\t" in replacements:
        return 3
    if any(line.rstrip() != line for line in replacements.splitlines()):
        return 3
    return 5


def score_candidate(
    candidate: PatchCandidate,
    build: StageResult,
    functional: StageResult,
    rescan: StageResult,
    exploit: StageResult,
) -> PatchScore:
    return PatchScore(
        security_test=_security_points(rescan, exploit),
        regression_test=_regression_points(functional),
        code_change_size=_change_size_points(candidate),
        build_stability=10 if build.status is StageStatus.PASS else 0,
        coding_style=_style_points(candidate),
    )
