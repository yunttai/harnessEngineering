import os
from pathlib import Path

from pydantic import BaseModel


class Settings(BaseModel):
    database_url: str = "sqlite:///attack2patch.db"
    workspace: Path = Path("work")
    demo_base_url: str = "http://demo-app:5000"
    deploy_approval_required: bool = True


def load_settings() -> Settings:
    return Settings(
        database_url=os.getenv("ATTACK2PATCH_DATABASE_URL", "sqlite:///attack2patch.db"),
        workspace=Path(os.getenv("ATTACK2PATCH_WORKSPACE", "work")),
        demo_base_url=os.getenv("ATTACK2PATCH_DEMO_BASE_URL", "http://demo-app:5000"),
        deploy_approval_required=os.getenv("ATTACK2PATCH_DEPLOY_APPROVAL_REQUIRED", "true").lower()
        == "true",
    )
