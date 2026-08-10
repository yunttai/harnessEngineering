from pathlib import Path

from attack2patch.types.attack_event import EventStatus
from attack2patch.types.patch import PatchStatus
from attack2patch.ui.api import create_app


def test_attack_to_patch_workflow(workflow_bundle):
    original_path = workflow_bundle.settings.demo_app_root / "app.py"
    original_source = original_path.read_text(encoding="utf-8")

    event = workflow_bundle.workflow.analyze(workflow_bundle.attack_record())
    assert event is not None
    assert event.status == EventStatus.CODE_LOCATED
    finding = workflow_bundle.repository.findings_for_event(event.id)[0]
    assert finding.file_path == "demo-app/app.py"
    assert finding.function_name == "get_users"
    assert "SELECT" in finding.vulnerable_code

    patch = workflow_bundle.workflow.generate_patch(event.id)
    assert patch.status == PatchStatus.GENERATED
    assert original_path.read_text(encoding="utf-8") == original_source

    patch = workflow_bundle.workflow.approve_patch(patch.id)
    assert patch.status == PatchStatus.APPROVED
    assert patch.workspace_path
    candidate = Path(patch.workspace_path) / patch.file_path
    assert "connection.execute(query, (name,))" in candidate.read_text(encoding="utf-8")
    assert original_path.read_text(encoding="utf-8") == original_source

    patch, validation = workflow_bundle.workflow.validate_patch(patch.id)
    assert validation.deployable
    assert patch.status == PatchStatus.VALIDATED
    assert workflow_bundle.repository.get(event.id).status == EventStatus.TEST_PASSED
    assert all(
        validation.as_dict()[gate]
        for gate in (
            "syntax_ok",
            "unit_tests_ok",
            "normal_request_ok",
            "attack_test_ok",
            "rescan_ok",
        )
    )


def test_normal_request_is_not_persisted_as_attack(workflow_bundle):
    record = workflow_bundle.attack_record(payload="alice")
    assert workflow_bundle.workflow.analyze(record) is None
    assert workflow_bundle.repository.list_events() == []


def test_sensitive_attack_input_is_detected_but_redacted(workflow_bundle):
    record = workflow_bundle.attack_record(payload="alice", password="' OR 1=1--")
    event = workflow_bundle.workflow.analyze(record)
    assert event is not None
    assert "REDACTED" in event.sanitized_payload
    assert "1=1" not in event.sanitized_payload


def test_api_rejects_missing_approval_and_exposes_dashboard_gates(workflow_bundle):
    app = create_app(
        workflow_bundle.settings,
        workflow_bundle.repository,
    )
    client = app.test_client()
    response = client.post(
        "/api/logs",
        json=workflow_bundle.attack_record().model_dump(mode="json"),
    )
    assert response.status_code == 201
    event_id = response.get_json()["event"]["id"]

    response = client.post(f"/api/events/{event_id}/patches", json={})
    assert response.status_code == 201
    patch_id = response.get_json()["patch"]["id"]
    assert client.post(f"/api/patches/{patch_id}/approve", json={}).status_code == 400

    page = client.get(f"/events/{event_id}").get_data(as_text=True)
    assert 'data-testid="patch-approve"' in page
    assert 'data-testid="deploy-approve"' in page
    deploy_button = page.split('data-testid="deploy-approve"', 1)[1].split(">", 1)[0]
    assert "disabled" in deploy_button

    assert client.post(
        f"/api/patches/{patch_id}/approve", json={"approved": True}
    ).status_code == 200
    assert client.post(f"/api/patches/{patch_id}/validate", json={}).status_code == 200
    page = client.get(f"/events/{event_id}").get_data(as_text=True)
    deploy_button = page.split('data-testid="deploy-approve"', 1)[1].split(">", 1)[0]
    assert "disabled" not in deploy_button
