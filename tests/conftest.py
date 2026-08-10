from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest

from attack2patch.config.settings import Settings
from attack2patch.repo.sqlite_repository import SQLiteRepository
from attack2patch.runtime.candidate_validator import validate_workspace
from attack2patch.runtime.log_collector import HttpLogRecord
from attack2patch.service.attack_workflow import AttackWorkflowService


@dataclass
class WorkflowBundle:
    settings: Settings
    repository: SQLiteRepository
    workflow: AttackWorkflowService

    def attack_record(self, payload: str = "' OR 1=1--", **parameters: str) -> HttpLogRecord:
        values = {"name": payload, **parameters}
        return HttpLogRecord(
            timestamp=datetime(2026, 8, 10, 10, 1, tzinfo=timezone.utc),
            method="GET",
            path="/api/users",
            parameters=values,
            source_ip="127.0.0.1",
            status_code=200,
        )


@pytest.fixture
def workflow_bundle(tmp_path: Path) -> WorkflowBundle:
    repository_root = Path(__file__).parents[1]
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'attack2patch.db'}",
        workspace=tmp_path / "work",
        repository_root=repository_root,
        demo_app_path=Path("demo-app"),
        compose_file=Path("docker-compose.yml"),
        demo_base_url="http://127.0.0.1:5000",
    )
    repository = SQLiteRepository(settings.database_url)
    return WorkflowBundle(
        settings=settings,
        repository=repository,
        workflow=AttackWorkflowService(settings, repository, validate_workspace),
    )
