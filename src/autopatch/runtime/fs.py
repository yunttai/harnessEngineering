from __future__ import annotations

import hashlib
from pathlib import Path


def ensure_within(root: Path, candidate: Path) -> Path:
    root_resolved = root.resolve()
    candidate_resolved = candidate.resolve()
    candidate_resolved.relative_to(root_resolved)
    return candidate_resolved


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_probably_binary(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:4096]
    except OSError:
        return True
    return b"\x00" in sample


def iter_source_files(
    root: Path,
    *,
    suffixes: set[str],
    excluded_directories: set[str],
    max_file_bytes: int,
) -> list[Path]:
    root = root.resolve()
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in excluded_directories for part in relative.parts):
            continue
        if path.suffix.lower() not in suffixes:
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                continue
        except OSError:
            continue
        if path.is_symlink():
            try:
                path.resolve().relative_to(root)
            except ValueError:
                continue
        if is_probably_binary(path):
            continue
        files.append(path)
    return sorted(files)
