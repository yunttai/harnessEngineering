import hashlib
from pathlib import Path


EXCLUDED_DIRECTORIES = {".pytest_cache", "__pycache__"}
EXCLUDED_SUFFIXES = {".db", ".pyc", ".pyo"}


def workspace_digest(workspace: Path) -> str:
    """Hash every build-relevant regular file and its relative path deterministically."""
    workspace = workspace.resolve()
    digest = hashlib.sha256()
    for path in sorted(workspace.rglob("*")):
        relative = path.relative_to(workspace)
        if any(part in EXCLUDED_DIRECTORIES for part in relative.parts):
            continue
        if path.suffix in EXCLUDED_SUFFIXES:
            continue
        if path.is_symlink():
            raise ValueError("validated workspace must not contain symlinks")
        if not path.is_file():
            continue
        relative_bytes = relative.as_posix().encode()
        content = path.read_bytes()
        digest.update(len(relative_bytes).to_bytes(8, "big"))
        digest.update(relative_bytes)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()
