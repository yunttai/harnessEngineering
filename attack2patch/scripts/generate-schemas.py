#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from autopatch.types import Finding, RunReport  # noqa: E402

SCHEMAS: dict[str, dict[str, Any]] = {
    "finding.schema.json": Finding.model_json_schema(),
    "run-report.schema.json": RunReport.model_json_schema(),
}


def render(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    destination = ROOT / "schemas"
    destination.mkdir(parents=True, exist_ok=True)
    stale: list[str] = []
    for name, schema in SCHEMAS.items():
        path = destination / name
        content = render(schema)
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                stale.append(name)
        else:
            path.write_text(content, encoding="utf-8")
            print(f"[schemas] wrote {path.relative_to(ROOT)}")
    if stale:
        print("[schemas] stale generated files: " + ", ".join(stale))
        print("[schemas] run: python scripts/generate-schemas.py")
        return 1
    if args.check:
        print("[schemas] generated schemas are current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
