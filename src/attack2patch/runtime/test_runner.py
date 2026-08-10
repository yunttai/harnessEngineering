import subprocess
from pathlib import Path


def run_pytest(repository: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python", "-m", "pytest", "-q"],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )
