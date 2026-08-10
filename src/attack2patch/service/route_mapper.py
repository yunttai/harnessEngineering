from pathlib import Path


def ensure_repository_path(repository_root: Path, candidate: Path) -> Path:
    resolved_root = repository_root.resolve()
    resolved_candidate = (resolved_root / candidate).resolve()
    if resolved_candidate != resolved_root and resolved_root not in resolved_candidate.parents:
        raise ValueError("candidate path escapes repository root")
    return resolved_candidate
