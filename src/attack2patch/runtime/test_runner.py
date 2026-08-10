import subprocess
import sys
from pathlib import Path


def run_pytest(
    repository: Path,
    timeout_seconds: float = 60.0,
    marker_expression: str | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, "-m", "pytest", "-q"]
    if marker_expression:
        command.extend(["-m", marker_expression])
    return subprocess.run(
        command,
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )
