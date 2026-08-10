#!/usr/bin/env bash
set -euo pipefail
if grep -RInE '(api[_-]?key|password|secret)[[:space:]]*=[[:space:]]*["'\'''][^"'\'']+' --exclude='.env.example' --exclude-dir='.git' .; then
  echo "Potential hard-coded secret found"
  exit 1
fi
