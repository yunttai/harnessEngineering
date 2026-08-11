from __future__ import annotations

import os
from pathlib import Path
from threading import Lock

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from autopatch.config import load_settings
from autopatch.runtime.factory import build_orchestrator
from autopatch.ui.common import validate_target

app = FastAPI(
    title="Attack2Patch",
    version="0.1.0",
    description="Local, verification-driven source patching API",
)

_run_lock = Lock()


class ScanRequest(BaseModel):
    target: str


class RunRequest(BaseModel):
    target: str
    apply: bool = False
    execute_tests: bool = False
    execute_security_tests: bool = False


class HealthResponse(BaseModel):
    status: str = Field(default="ok")
    config: str


def _config_path() -> Path:
    return Path(os.getenv("AUTOPATCH_CONFIG", "config/harness.yaml")).resolve()


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(config=str(_config_path()))


@app.post("/v1/scan")
def scan(request: ScanRequest) -> dict[str, object]:
    try:
        config_path = _config_path()
        settings = load_settings(config_path)
        target = validate_target(Path(request.target), settings)
        orchestrator = build_orchestrator(settings=settings, config_path=config_path)
        result = orchestrator.detection.scan(target)
        return {
            "target": str(target),
            "findings": [item.model_dump(mode="json") for item in result.findings],
            "errors": result.errors,
            "skipped": result.skipped,
            "executed": result.executed,
        }
    except (OSError, ValueError, PermissionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/run")
def run(request: RunRequest) -> dict[str, object]:
    if request.apply:
        raise HTTPException(
            status_code=403,
            detail="API apply is disabled in the MVP; use the local CLI with explicit --apply",
        )
    if not _run_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="another run is active")
    try:
        config_path = _config_path()
        settings = load_settings(config_path)
        if (request.execute_tests or request.execute_security_tests) and not settings.autonomy.execute_tests:
            raise HTTPException(
                status_code=403,
                detail=(
                    "API test execution requires autonomy.execute_tests=true in the "
                    "selected configuration"
                ),
            )
        target = validate_target(Path(request.target), settings)
        orchestrator = build_orchestrator(
            settings=settings,
            config_path=config_path,
            execute_tests=request.execute_tests,
            execute_security_tests=request.execute_security_tests,
        )
        report = orchestrator.run(target, apply=False)
        return report.model_dump(mode="json")
    except (OSError, ValueError, PermissionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        _run_lock.release()


@app.get("/v1/runs/{run_id}")
def run_status(run_id: str) -> dict[str, object]:
    try:
        config_path = _config_path()
        settings = load_settings(config_path)
        orchestrator = build_orchestrator(settings=settings, config_path=config_path)
        report = orchestrator.store.read_run(run_id)
        return report.model_dump(mode="json")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="run not found") from exc
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
