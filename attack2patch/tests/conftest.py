from __future__ import annotations

import shutil
from pathlib import Path

import pytest


@pytest.fixture
def repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def vulnerable_project(tmp_path: Path, repository_root: Path) -> Path:
    source = repository_root / "examples" / "vulnerable_flask"
    destination = tmp_path / "target"
    shutil.copytree(source, destination)
    return destination
