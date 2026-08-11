#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

if [[ -z "${PYTHON_BIN:-}" && -x "$ROOT/.venv/Scripts/python.exe" ]]; then
  PYTHON_BIN="$ROOT/.venv/Scripts/python.exe"
elif [[ -z "${PYTHON_BIN:-}" && -x "$ROOT/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT/.venv/bin/python"
else
  PYTHON_BIN="${PYTHON_BIN:-python}"
fi
if ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' 2>/dev/null; then
  if command -v python.exe >/dev/null 2>&1; then
    PYTHON_BIN=python.exe
  else
    echo "Python 3.11 or newer is required" >&2
    exit 1
  fi
fi

run() {
  local name="$1"
  shift
  echo "==> $name"
  "$@"
}

run "repository map" bash scripts/check-agents-map.sh
run "Markdown links" "$PYTHON_BIN" scripts/check-links.py
run "architecture" "$PYTHON_BIN" scripts/check-architecture.py
run "configuration" "$PYTHON_BIN" scripts/check-config.py
run "generated schemas" "$PYTHON_BIN" scripts/generate-schemas.py --check
run "secret scan" "$PYTHON_BIN" scripts/check-secrets.py
run "Python compile" "$PYTHON_BIN" -m compileall -q src tests examples scripts
run "unit/integration tests" "$PYTHON_BIN" -m pytest -q

echo
echo "all harness checks passed"
