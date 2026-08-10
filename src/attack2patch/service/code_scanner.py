from pathlib import Path


def scan_file(path: Path) -> list[int]:
    """MVP heuristic; replace with a tested Semgrep rule during implementation."""
    findings: list[int] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if "SELECT" in line.upper() and ("f\"" in line or "+" in line):
            findings.append(line_number)
    return findings
