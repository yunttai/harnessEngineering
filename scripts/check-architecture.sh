#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${PYTHON_BIN:-}" ]]; then
  python_bin="$PYTHON_BIN"
elif command -v python.exe >/dev/null 2>&1 && python.exe -c "" >/dev/null 2>&1; then
  python_bin="python.exe"
else
  python_bin="python"
fi
test -f AGENTS.md
test -f ARCHITECTURE.md
test -f docs/product-specs/attack2patch-prd.md
"$python_bin" scripts/check_architecture.py
