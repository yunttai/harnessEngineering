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
  "attack2patch/README.md"
  "attack2patch/pyproject.toml"
  "attack2patch/Dockerfile"
  "attack2patch/docker-compose.yml"
  "attack2patch/config/harness.yaml"
  "attack2patch/config/tools.yaml"
  "attack2patch/runbooks/rollback.md"
  "docs/index.md"
  "docs/CODE_READING_GUIDE.md"
  "docs/AGENT_TEAM.md"
  "docs/DESIGN.md"
  "docs/SECURITY.md"
  "docs/RELIABILITY.md"
  "docs/PLANS.md"
  "docs/QUALITY_SCORE.md"
  "docs/product-specs/PRD.md"
  "docs/exec-plans/tech-debt-tracker.md"
  "attack2patch/src/autopatch/types"
  "attack2patch/src/autopatch/config"
  "attack2patch/src/autopatch/providers"
  "attack2patch/src/autopatch/repo"
  "attack2patch/src/autopatch/service"
  "attack2patch/src/autopatch/runtime"
  "attack2patch/src/autopatch/ui"
  "attack2patch/tests"
  "attack2patch/examples/vulnerable_flask"
  "attack2patch/scripts/check.sh"
)

failed=0
for path in "${required[@]}"; do
  if [[ ! -e "$ROOT/$path" ]]; then
    echo "[map] missing: $path"
    failed=1
  fi
done

legacy_product_paths=(
  "pyproject.toml"
  "Dockerfile"
  "docker-compose.yml"
  "config"
  "rules"
  "schemas"
  "src"
  "tests"
  "examples"
)
for path in "${legacy_product_paths[@]}"; do
  if [[ -e "$ROOT/$path" ]]; then
    echo "[map] product path must live under attack2patch/: $path"
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
