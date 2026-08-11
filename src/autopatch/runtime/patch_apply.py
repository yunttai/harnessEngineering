from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from autopatch.runtime.fs import ensure_within, sha256_file
from autopatch.types import PatchCandidate, TextEdit


def apply_edits_to_text(text: str, edits: list[TextEdit]) -> str:
    lines = text.splitlines(keepends=True)
    ordered = sorted(edits, key=lambda edit: (edit.start_line, edit.end_line), reverse=True)

    previous_start = len(lines) + 1
    for edit in ordered:
        if edit.end_line >= previous_start:
            raise ValueError("overlapping TextEdit ranges")
        if edit.end_line > len(lines):
            raise ValueError(
                f"edit range {edit.start_line}-{edit.end_line} exceeds file length {len(lines)}"
            )
        replacement = edit.replacement
        if replacement and not replacement.endswith("\n"):
            replacement += "\n"
        replacement_lines = replacement.splitlines(keepends=True)
        lines[edit.start_line - 1 : edit.end_line] = replacement_lines
        previous_start = edit.start_line
    return "".join(lines)


class SafePatchApplier:
    name = "safe-text-edit-applier"

    def apply(self, target: Path, candidate: PatchCandidate) -> None:
        target = target.resolve()
        grouped: dict[str, list[TextEdit]] = defaultdict(list)
        for edit in candidate.edits:
            grouped[edit.file].append(edit)

        pending: dict[Path, str] = {}
        for relative, edits in grouped.items():
            path = ensure_within(target, target / relative)
            if not path.is_file():
                raise FileNotFoundError(path)
            expected_hashes = {edit.original_sha256 for edit in edits}
            if len(expected_hashes) != 1:
                raise ValueError(f"inconsistent original hashes for {relative}")
            current_hash = sha256_file(path)
            expected = next(iter(expected_hashes))
            if current_hash != expected:
                raise RuntimeError(
                    f"original file changed for {relative}: expected {expected}, got {current_hash}"
                )
            current_text = path.read_text(encoding="utf-8")
            pending[path] = apply_edits_to_text(current_text, edits)

        # Write only after every file/hash/edit has been validated.
        for path, new_text in pending.items():
            path.write_text(new_text, encoding="utf-8")
