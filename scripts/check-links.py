#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_FILES = [ROOT / "README.md", ROOT / "AGENTS.md", ROOT / "ARCHITECTURE.md"]
MARKDOWN_FILES.extend(sorted((ROOT / "docs").rglob("*.md")))
MARKDOWN_FILES.extend(sorted((ROOT / "attack2patch").rglob("*.md")))
LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


def normalize_target(raw: str) -> str:
    target = raw.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1]
    # Markdown permits an optional quoted title after the URL.
    if " \"" in target:
        target = target.split(" \"", 1)[0]
    return unquote(target)


def main() -> int:
    failures: list[str] = []
    for document in MARKDOWN_FILES:
        text = document.read_text(encoding="utf-8")
        for match in LINK_RE.finditer(text):
            target = normalize_target(match.group(1))
            if not target or target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            file_part = target.split("#", 1)[0]
            if not file_part:
                continue
            destination = (document.parent / file_part).resolve()
            try:
                destination.relative_to(ROOT)
            except ValueError:
                failures.append(f"{document.relative_to(ROOT)} -> outside root: {target}")
                continue
            if not destination.exists():
                failures.append(f"{document.relative_to(ROOT)} -> missing: {target}")

    if failures:
        for failure in failures:
            print(f"[links] {failure}")
        return 1
    print(f"[links] validated {len(MARKDOWN_FILES)} Markdown files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
