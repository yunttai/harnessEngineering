#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$ROOT/.autopatch"
TEMP="$(mktemp -d "$ROOT/.autopatch/demo.XXXXXX")"
trap 'rm -rf "$TEMP"' EXIT
cp -a "$ROOT/examples/vulnerable_flask/." "$TEMP/target/"

cd "$ROOT"
if [[ -z "${PYTHON_BIN:-}" && -x "$ROOT/.venv/Scripts/python.exe" ]]; then
  PYTHON_BIN="$ROOT/.venv/Scripts/python.exe"
elif [[ -z "${PYTHON_BIN:-}" && -x "$ROOT/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT/.venv/bin/python"
elif [[ -z "${PYTHON_BIN:-}" && -x "$ROOT/../.venv/Scripts/python.exe" ]]; then
  PYTHON_BIN="$ROOT/../.venv/Scripts/python.exe"
elif [[ -z "${PYTHON_BIN:-}" && -x "$ROOT/../.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT/../.venv/bin/python"
else
  PYTHON_BIN="${PYTHON_BIN:-python}"
fi
TARGET_ARG="$TEMP/target"
CONFIG_ARG="$ROOT/config/harness.yaml"
CLI_ARG="$ROOT/scripts/run-cli.py"
if ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' 2>/dev/null; then
  if command -v python.exe >/dev/null 2>&1; then
    PYTHON_BIN=python.exe
  else
    echo "Python 3.11 or newer is required" >&2
    exit 1
  fi
fi
PYTHON_OS="$("$PYTHON_BIN" -c 'import os; print(os.name)' | tr -d '\r')"
if [[ "$PYTHON_OS" == "nt" ]]; then
  TARGET_ARG="$(wslpath -w "$TARGET_ARG")"
  CONFIG_ARG="$(wslpath -w "$CONFIG_ARG")"
  CLI_ARG="$(wslpath -w "$CLI_ARG")"
fi

"$PYTHON_BIN" "$CLI_ARG" run "$TARGET_ARG" \
  --config "$CONFIG_ARG" \
  --execute-tests \
  --execute-security-tests \
  --apply

echo
echo "patched source:"
sed -n '20,32p' "$TEMP/target/app.py"
echo
echo "post-patch findings:"
"$PYTHON_BIN" "$CLI_ARG" scan "$TARGET_ARG" --config "$CONFIG_ARG"
