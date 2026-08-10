#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${PYTHON_BIN:-}" ]]; then
  python_bin="$PYTHON_BIN"
elif command -v python.exe >/dev/null 2>&1 && python.exe -c "" >/dev/null 2>&1; then
  python_bin="python.exe"
else
  python_bin="python"
fi
"$python_bin" -m pytest -q
"$python_bin" -m compileall -q src demo-app
"$python_bin" -m ruff check src tests demo-app scripts/check_architecture.py scripts/check_secrets.py scripts/verify_docker_rollback.py
PYTHON_BIN="$python_bin" bash scripts/check-architecture.sh
PYTHON_BIN="$python_bin" bash scripts/check-secrets.sh
