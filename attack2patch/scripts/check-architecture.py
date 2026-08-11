#!/usr/bin/env python3
from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "autopatch"

ALLOWED: dict[str, set[str]] = {
    "types": {"types"},
    "config": {"types", "config"},
    "providers": {"types", "providers"},
    "repo": {"types", "config", "providers", "repo"},
    "service": {"types", "config", "providers", "repo", "service"},
    "runtime": {"types", "config", "providers", "repo", "service", "runtime"},
    "ui": {"types", "config", "providers", "repo", "service", "runtime", "ui"},
}


def imported_layer(module: str | None) -> str | None:
    if not module or not module.startswith("autopatch."):
        return None
    parts = module.split(".")
    return parts[1] if len(parts) > 1 else None


def main() -> int:
    failures: list[str] = []
    for source in sorted(PACKAGE.rglob("*.py")):
        relative = source.relative_to(PACKAGE)
        if len(relative.parts) < 2:
            continue
        current = relative.parts[0]
        if current not in ALLOWED:
            continue
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(relative))
        for node in ast.walk(tree):
            targets: list[str] = []
            if isinstance(node, ast.Import):
                targets.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                targets.append(node.module or "")
            else:
                continue
            for module in targets:
                target = imported_layer(module)
                if target and target not in ALLOWED[current]:
                    failures.append(
                        f"{relative}:{getattr(node, 'lineno', 0)}: "
                        f"{current} must not import higher layer {target} ({module})"
                    )

    if failures:
        for failure in failures:
            print(f"[architecture] {failure}")
        return 1
    print("[architecture] layer imports satisfy the dependency map")
    return 0


if __name__ == "__main__":
    sys.exit(main())
