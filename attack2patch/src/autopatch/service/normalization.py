from __future__ import annotations

import hashlib
from pathlib import PurePosixPath


def normalize_relative_path(value: str) -> str:
    raw = value.replace("\\", "/").strip()
    while raw.startswith("./"):
        raw = raw[2:]
    if not raw or raw == ".":
        raise ValueError("relative path is empty")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".."} for part in path.parts):
        raise ValueError(f"unsafe relative path: {value}")
    normalized = path.as_posix()
    if normalized.startswith("/"):
        raise ValueError(f"unsafe relative path: {value}")
    return normalized


def make_fingerprint(
    *,
    scanner: str,
    rule_id: str | None,
    cwe: str,
    file: str,
    line: int,
    semantic_key: str = "",
) -> str:
    payload = "\n".join(
        [
            scanner.strip().lower(),
            (rule_id or "").strip().lower(),
            cwe.strip().upper(),
            normalize_relative_path(file),
            str(line),
            semantic_key.strip(),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def finding_id_from_fingerprint(fingerprint: str) -> str:
    return f"VULN-{fingerprint[:12].upper()}"
