import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field, field_validator

from attack2patch.types.base import StrictModel


class Settings(StrictModel):
    database_url: str = "sqlite:///attack2patch.db"
    workspace: Path = Path("work")
    repository_root: Path = Field(default_factory=Path.cwd)
    demo_app_path: Path = Path("demo-app")
    compose_file: Path = Path("docker-compose.yml")
    compose_project_name: str = "attack2patch"
    access_log_path: Path | None = None
    demo_base_url: str = "http://demo-app:5000"
    deploy_approval_required: bool = True
    baseline_image: str = "attack2patch-demo:baseline"

    @field_validator("database_url")
    @classmethod
    def sqlite_only(cls, value: str) -> str:
        if not value.startswith("sqlite:///"):
            raise ValueError("MVP supports only sqlite:/// database URLs")
        return value

    @field_validator("demo_base_url")
    @classmethod
    def local_demo_url_only(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme != "http" or parsed.hostname not in {"demo-app", "127.0.0.1", "localhost"}:
            raise ValueError("demo URL must use HTTP and the isolated local demo host")
        return value.rstrip("/")

    @field_validator("baseline_image")
    @classmethod
    def validate_baseline_image(cls, value: str) -> str:
        if not re.fullmatch(r"attack2patch-demo:[a-z0-9][a-z0-9._-]{0,63}", value):
            raise ValueError("baseline image tag is outside the allowlist")
        return value

    @field_validator("compose_project_name")
    @classmethod
    def validate_compose_project_name(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", value):
            raise ValueError("Compose project name is outside the allowlist")
        return value

    @property
    def demo_app_root(self) -> Path:
        return (self.repository_root / self.demo_app_path).resolve()

    @property
    def resolved_workspace(self) -> Path:
        path = self.workspace
        if not path.is_absolute():
            path = self.repository_root / path
        return path.resolve()

    @property
    def resolved_compose_file(self) -> Path:
        path = self.compose_file
        if not path.is_absolute():
            path = self.repository_root / path
        return path.resolve()


def load_settings() -> Settings:
    repository_root = Path(os.getenv("ATTACK2PATCH_REPOSITORY_ROOT", Path.cwd()))
    return Settings(
        database_url=os.getenv("ATTACK2PATCH_DATABASE_URL", "sqlite:///attack2patch.db"),
        workspace=Path(os.getenv("ATTACK2PATCH_WORKSPACE", "work")),
        repository_root=repository_root,
        demo_app_path=Path(os.getenv("ATTACK2PATCH_DEMO_APP_PATH", "demo-app")),
        compose_file=Path(os.getenv("ATTACK2PATCH_COMPOSE_FILE", "docker-compose.yml")),
        compose_project_name=os.getenv("ATTACK2PATCH_COMPOSE_PROJECT_NAME", "attack2patch"),
        access_log_path=(
            Path(os.environ["ATTACK2PATCH_ACCESS_LOG_PATH"])
            if os.getenv("ATTACK2PATCH_ACCESS_LOG_PATH")
            else None
        ),
        demo_base_url=os.getenv("ATTACK2PATCH_DEMO_BASE_URL", "http://demo-app:5000"),
        deploy_approval_required=os.getenv("ATTACK2PATCH_DEPLOY_APPROVAL_REQUIRED", "true").lower()
        == "true",
        baseline_image=os.getenv("ATTACK2PATCH_BASELINE_IMAGE", "attack2patch-demo:baseline"),
    )
