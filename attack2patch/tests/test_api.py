from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from autopatch.ui.api import app


def test_health_exposes_config_path(repository_root: Path, monkeypatch) -> None:
    config = repository_root / "config" / "harness.yaml"
    monkeypatch.setenv("AUTOPATCH_CONFIG", str(config))
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["config"] == str(config.resolve())


def test_api_refuses_source_mutation(vulnerable_project: Path, repository_root: Path, monkeypatch) -> None:
    monkeypatch.setenv(
        "AUTOPATCH_CONFIG",
        str(repository_root / "config" / "harness.yaml"),
    )
    response = TestClient(app).post(
        "/v1/run",
        json={"target": str(vulnerable_project), "apply": True},
    )
    assert response.status_code == 403


def test_api_refuses_test_execution_without_config_gate(
    vulnerable_project: Path,
    repository_root: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "AUTOPATCH_CONFIG",
        str(repository_root / "config" / "harness.yaml"),
    )
    response = TestClient(app).post(
        "/v1/run",
        json={"target": str(vulnerable_project), "execute_tests": True},
    )
    assert response.status_code == 403


def test_api_exposes_persisted_run_status(
    vulnerable_project: Path,
    repository_root: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(
        "AUTOPATCH_CONFIG",
        str(repository_root / "config" / "harness.yaml"),
    )
    client = TestClient(app)
    started = client.post(
        "/v1/run",
        json={"target": str(vulnerable_project), "use_llm": False},
    )
    assert started.status_code == 200
    run_id = started.json()["run_id"]

    status = client.get(f"/v1/runs/{run_id}")

    assert status.status_code == 200
    assert status.json()["run_id"] == run_id
    assert status.json()["state"] == "VERIFIED"


def test_api_scan_does_not_initialize_default_llm(
    vulnerable_project: Path,
    repository_root: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "AUTOPATCH_CONFIG",
        str(repository_root / "config" / "harness.yaml"),
    )

    response = TestClient(app).post(
        "/v1/scan",
        json={"target": str(vulnerable_project)},
    )

    assert response.status_code == 200
    assert len(response.json()["findings"]) == 1
