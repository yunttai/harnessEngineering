#!/usr/bin/env python3
"""Run the source checkout CLI without requiring an editable installation."""

from __future__ import annotations

import sys
from pathlib import Path

PRODUCT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PRODUCT_ROOT / "src"))

from autopatch.ui.cli import app  # noqa: E402


if __name__ == "__main__":
    app()
