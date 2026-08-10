import re
from pathlib import Path


SECRET_ASSIGNMENT = re.compile(
    r"(?i)(api[_-]?key|password|secret)\s*=\s*[\"'][^\"'\r\n]+[\"']"
)
EXCLUDED_DIRECTORIES = {".git", ".pytest_cache", ".venv", "__pycache__", "build", "dist", "work"}
EXCLUDED_FILES = {".env.example"}


def main() -> int:
    root = Path(__file__).parents[1]
    findings: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.name in EXCLUDED_FILES:
            continue
        if any(part in EXCLUDED_DIRECTORIES for part in path.relative_to(root).parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            if SECRET_ASSIGNMENT.search(line):
                findings.append(f"{path.relative_to(root)}:{line_number}: potential hard-coded secret")
    if findings:
        print("\n".join(findings))
        return 1
    print("Secret assignment check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
