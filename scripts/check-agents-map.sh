#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

required=(
  "AGENTS.md"
  "ARCHITECTURE.md"
  "README.md"
  ".opencode/agent/orchestrator.md"
  ".opencode/agent/detector.md"
  ".opencode/agent/analyzer.md"
  ".opencode/agent/patcher.md"
  ".opencode/agent/verifier.md"
  ".opencode/agent/reviewer.md"
  ".opencode/agent/security.md"
  ".opencode/agent/committer.md"
  ".opencode/agent/deployer.md"
  "config/harness.yaml"
  "config/tools.yaml"
  "docs/index.md"
  "docs/AGENT_TEAM.md"
  "docs/DESIGN.md"
  "docs/SECURITY.md"
  "docs/RELIABILITY.md"
  "docs/PLANS.md"
  "docs/QUALITY_SCORE.md"
  "docs/product-specs/PRD.md"
  "docs/exec-plans/tech-debt-tracker.md"
  "src/autopatch/types"
  "src/autopatch/config"
  "src/autopatch/providers"
  "src/autopatch/repo"
  "src/autopatch/service"
  "src/autopatch/runtime"
  "src/autopatch/ui"
  "tests"
  "examples/vulnerable_flask"
)

failed=0
for path in "${required[@]}"; do
  if [[ ! -e "$ROOT/$path" ]]; then
    echo "[map] missing: $path"
    failed=1
  fi
done

agents_lines=$(wc -l < "$ROOT/AGENTS.md")
if (( agents_lines > 140 )); then
  echo "[map] AGENTS.md is ${agents_lines} lines; keep it as a concise map (<= 140)."
  failed=1
fi

if (( failed )); then
  exit 1
fi

echo "[map] repository map is synchronized"
