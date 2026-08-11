from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from autopatch.config import HarnessSettings


def validate_target(target: Path, settings: HarnessSettings) -> Path:
    resolved = target.expanduser().resolve()
    if not resolved.is_dir():
        raise NotADirectoryError(resolved)

    if settings.scope.local_paths_only and "://" in str(target):
        raise ValueError("only local filesystem paths are allowed")

    if settings.scope.authorized_targets:
        allowed = [Path(value).expanduser().resolve() for value in settings.scope.authorized_targets]
        if not any(_is_within(resolved, root) for root in allowed):
            raise PermissionError(
                f"target {resolved} is not under any configured authorized_targets entry"
            )
    return resolved


def _is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def validate_dast_target(value: str, settings: HarnessSettings) -> str:
    if not settings.dast.enabled:
        raise PermissionError("DAST is disabled")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("DAST target must be an HTTP(S) URL")
    normalized = value.rstrip("/")
    authorized = {target.rstrip("/") for target in settings.dast.authorized_targets}
    if normalized not in authorized:
        raise PermissionError("DAST target is not explicitly authorized")
    return normalized
