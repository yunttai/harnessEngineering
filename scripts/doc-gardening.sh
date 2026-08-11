#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== documentation gardening =="
echo "active plans:"
for file in docs/exec-plans/active/*.md; do
  [[ -e "$file" ]] || continue
  status=$(grep -m1 '^- 상태:' "$file" || true)
  printf '  - %s: %s\n' "$(basename "$file")" "${status:-- 상태: 누락}"
done

echo
echo "draft/TODO markers:"
markers=$(grep -RInE 'TODO|TBD|상태: DRAFT|\(예정\)' docs --include='*.md' || true)
if [[ -n "$markers" ]]; then
  printf '%s\n' "$markers"
else
  echo "  none"
fi

echo
echo "quality and debt files:"
echo "  - docs/QUALITY_SCORE.md"
echo "  - docs/exec-plans/tech-debt-tracker.md"
echo
echo "run 'bash scripts/check.sh' after documentation changes"
