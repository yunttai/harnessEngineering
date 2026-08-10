#!/usr/bin/env bash
set -euo pipefail
find docs -type f -name '*.md' -print | sort
