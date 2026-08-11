#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_DIRS = {".git", ".venv", ".autopatch", "__pycache__", "dist", "build"}
EXCLUDED_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".zip", ".gz", ".pyc"}
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub classic token", re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
    ("OpenAI-style secret", re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)


def main() -> int:
    findings: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() in EXCLUDED_SUFFIXES:
            continue
        if any(part in EXCLUDED_DIRS for part in path.relative_to(ROOT).parts):
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for line_no, line in enumerate(content.splitlines(), start=1):
            for label, pattern in PATTERNS:
                if pattern.search(line):
                    findings.append(f"{path.relative_to(ROOT)}:{line_no}: {label}")

    if findings:
        for finding in findings:
            print(f"[secrets] {finding}")
        return 1
    print("[secrets] no high-confidence secret patterns found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
