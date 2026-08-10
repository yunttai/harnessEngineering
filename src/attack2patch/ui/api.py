from typing import Literal, TypeVar

from flask import Flask, jsonify, render_template_string, request
from pydantic import ValidationError

from attack2patch.config.settings import Settings, load_settings
from attack2patch.repo.sqlite_repository import SQLiteRepository
from attack2patch.runtime.candidate_validator import validate_workspace
from attack2patch.runtime.compose_deployer import ComposeDeployer
from attack2patch.runtime.health_checker import PostDeploymentVerifier
from attack2patch.runtime.image_builder import DockerImageBuilder
from attack2patch.runtime.log_collector import FileLogCollector, HttpLogRecord
from attack2patch.service.attack_workflow import AttackWorkflowService, WorkflowError
from attack2patch.service.deployment_service import DeploymentService
from attack2patch.types.base import StrictModel
from attack2patch.types.patch import PatchStatus


class ApprovalRequest(StrictModel):
    approved: Literal[True]


ModelT = TypeVar("ModelT", bound=StrictModel)


def create_app(
    settings: Settings | None = None,
    repository: SQLiteRepository | None = None,
    deployment_service: DeploymentService | None = None,
) -> Flask:
    settings = settings or load_settings()
    repository = repository or SQLiteRepository(settings.database_url)
    workflow = AttackWorkflowService(settings, repository, validate_workspace)
    deployment_service = deployment_service or DeploymentService(
        settings,
        repository,
        builder=DockerImageBuilder(),
        deployer=ComposeDeployer(
            settings.resolved_compose_file, settings.compose_project_name
        ),
        verifier=PostDeploymentVerifier(settings.demo_base_url),
    )

    app = Flask(__name__)
    app.config.update(
        ATTACK2PATCH_SETTINGS=settings,
        ATTACK2PATCH_REPOSITORY=repository,
        ATTACK2PATCH_WORKFLOW=workflow,
        ATTACK2PATCH_DEPLOYMENT_SERVICE=deployment_service,
    )
    if settings.access_log_path:
        collector = FileLogCollector(settings.access_log_path, workflow.analyze)
        collector.start()
        app.extensions["attack2patch_log_collector"] = collector

    @app.errorhandler(ValidationError)
    def validation_error(exc: ValidationError):
        return jsonify(error="invalid_request", details=exc.errors(include_url=False)), 400

    @app.errorhandler(LookupError)
    def not_found(exc: LookupError):
        return jsonify(error="not_found", details=str(exc)), 404

    @app.errorhandler(PermissionError)
    def forbidden(exc: PermissionError):
        return jsonify(error="approval_required", details=str(exc)), 403

    @app.errorhandler(WorkflowError)
    @app.errorhandler(RuntimeError)
    def conflict(exc: RuntimeError):
        return jsonify(error="invalid_state", details=str(exc)), 409

    @app.errorhandler(ValueError)
    def bad_request(exc: ValueError):
        return jsonify(error="invalid_request", details=str(exc)), 400

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.post("/api/logs")
    def collect_log():
        record = _request_model(HttpLogRecord)
        event = workflow.analyze(record)
        if not event:
            return jsonify(detected=False), 202
        return jsonify(detected=True, event=event.model_dump(mode="json")), 201

    @app.get("/api/events")
    def list_events():
        return jsonify(
            events=[event.model_dump(mode="json") for event in repository.list_events()]
        )

    @app.get("/api/events/<event_id>")
    def event_details(event_id: str):
        return jsonify(_serialize_details(workflow.event_details(event_id)))

    @app.post("/api/events/<event_id>/patches")
    def generate_patch(event_id: str):
        _require_empty_json_body()
        patch = workflow.generate_patch(event_id)
        return jsonify(patch=patch.model_dump(mode="json")), 201

    @app.post("/api/patches/<patch_id>/approve")
    def approve_patch(patch_id: str):
        _request_model(ApprovalRequest)
        patch = workflow.approve_patch(patch_id)
        return jsonify(patch=patch.model_dump(mode="json"))

    @app.post("/api/patches/<patch_id>/reject")
    def reject_patch(patch_id: str):
        _request_model(ApprovalRequest)
        patch = workflow.reject_patch(patch_id)
        return jsonify(patch=patch.model_dump(mode="json"))

    @app.post("/api/patches/<patch_id>/validate")
    def validate_patch(patch_id: str):
        _require_empty_json_body()
        patch, result = workflow.validate_patch(patch_id)
        status = 200 if result.deployable else 422
        return jsonify(
            patch=patch.model_dump(mode="json"), validation=result.as_dict()
        ), status

    @app.post("/api/patches/<patch_id>/deploy")
    def deploy_patch(patch_id: str):
        approval = _request_model(ApprovalRequest)
        deployment = deployment_service.deploy_patch(patch_id, approved=approval.approved)
        status = 201 if deployment.status.value == "COMPLETED" else 422
        return jsonify(deployment=deployment.model_dump(mode="json")), status

    @app.post("/api/deployments/<deployment_id>/rollback")
    def rollback(deployment_id: str):
        approval = _request_model(ApprovalRequest)
        deployment = deployment_service.manual_rollback(
            deployment_id, approved=approval.approved
        )
        return jsonify(deployment=deployment.model_dump(mode="json"))

    @app.get("/")
    def dashboard():
        return render_template_string(DASHBOARD_TEMPLATE, events=repository.list_events())

    @app.get("/events/<event_id>")
    def event_page(event_id: str):
        details = workflow.event_details(event_id)
        patches = details["patches"]
        deployments = details["deployments"]
        patch = patches[-1] if patches else None
        deployment = deployments[-1] if deployments else None
        return render_template_string(
            EVENT_TEMPLATE,
            **details,
            patch=patch,
            deployment=deployment,
            PatchStatus=PatchStatus,
        )

    return app


def _request_model(model: type[ModelT]) -> ModelT:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ValueError("request body must be a JSON object")
    return model.model_validate(body)


def _require_empty_json_body() -> None:
    body = request.get_json(silent=True)
    if body not in ({}, None):
        raise ValueError("this endpoint accepts only an empty JSON object")


def _serialize_details(details: dict[str, object]) -> dict[str, object]:
    serialized: dict[str, object] = {}
    for key, value in details.items():
        if isinstance(value, list):
            serialized[key] = [
                item.model_dump(mode="json") if isinstance(item, StrictModel) else item
                for item in value
            ]
        elif isinstance(value, StrictModel):
            serialized[key] = value.model_dump(mode="json")
        else:
            serialized[key] = value
    return serialized


DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Attack2Patch — Demo Only</title>
  <style>
    :root { color-scheme: dark; font-family: system-ui, sans-serif; }
    body { max-width: 1100px; margin: 2rem auto; padding: 0 1rem; background: #10131a; color: #eef2ff; }
    .warning { border-left: .35rem solid #f59e0b; padding: .8rem; background: #271d0c; }
    table { width: 100%; border-collapse: collapse; margin-top: 1.5rem; }
    th, td { padding: .75rem; border-bottom: 1px solid #334155; text-align: left; }
    a { color: #67e8f9; } .empty { color: #94a3b8; padding: 2rem 0; }
  </style>
</head>
<body>
  <h1 data-testid="dashboard-title">Attack2Patch</h1>
  <p class="warning" data-testid="demo-warning">격리된 데모 전용 — 운영 환경에 사용하지 마세요.</p>
  <h2>공격 이벤트</h2>
  {% if events %}
  <table data-testid="attack-event-list">
    <thead><tr><th>탐지 시각</th><th>공격 유형</th><th>대상 API</th><th>위험도</th><th>상태</th></tr></thead>
    <tbody>
    {% for event in events %}
      <tr data-testid="attack-event-row">
        <td>{{ event.detected_at.isoformat() }}</td><td>{{ event.attack_type.value }}</td>
        <td><a href="/events/{{ event.id }}">{{ event.path }}</a></td>
        <td>{{ event.severity.value }}</td><td data-testid="event-status">{{ event.status.value }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}<p class="empty" data-testid="empty-events">탐지된 공격이 없습니다.</p>{% endif %}
</body>
</html>
"""


EVENT_TEMPLATE = """
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Attack2Patch Event</title>
  <style>
    :root { color-scheme: dark; font-family: system-ui, sans-serif; }
    body { max-width: 1100px; margin: 2rem auto; padding: 0 1rem; background: #10131a; color: #eef2ff; }
    section { border: 1px solid #334155; border-radius: .6rem; padding: 1rem; margin: 1rem 0; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #080b11; padding: 1rem; }
    button { padding: .55rem .8rem; margin-right: .4rem; } button:disabled { opacity: .45; }
    .error { color: #fca5a5; } a { color: #67e8f9; }
  </style>
</head>
<body>
  <a href="/">← 이벤트 목록</a>
  <h1>공격 및 코드 상세</h1>
  <section data-testid="attack-detail">
    <p><strong>상태:</strong> <span data-testid="event-status">{{ event.status.value }}</span></p>
    <p><strong>요청:</strong> {{ event.method.value }} {{ event.path }}</p>
    <p><strong>마스킹된 입력:</strong> {{ event.sanitized_payload }}</p>
    <p><strong>탐지 근거:</strong> {{ event.evidence }}</p>
    {% if event.error %}<p class="error" data-testid="failure-reason">{{ event.error }}</p>{% endif %}
  </section>
  <section data-testid="code-finding">
    <h2>취약 코드</h2>
    {% for finding in findings %}
      <p>{{ finding.file_path }} · {{ finding.function_name }} · line {{ finding.line_number }}</p>
      <pre>{{ finding.vulnerable_code }}</pre>
    {% else %}<p>코드 매핑 결과가 없습니다.</p>{% endfor %}
  </section>
  <section data-testid="patch-panel">
    <h2>패치</h2>
    {% if patch %}
      <p data-testid="patch-status">{{ patch.status.value }}</p><p>{{ patch.reason }}</p>
      <pre data-testid="patch-diff">{{ patch.diff }}</pre>
      <button data-testid="patch-approve" onclick="post('/api/patches/{{ patch.id }}/approve', {approved:true})" {% if patch.status != PatchStatus.GENERATED %}disabled{% endif %}>패치 승인</button>
      <button data-testid="patch-reject" onclick="post('/api/patches/{{ patch.id }}/reject', {approved:true})" {% if patch.status != PatchStatus.GENERATED %}disabled{% endif %}>거절</button>
      <button data-testid="patch-validate" onclick="post('/api/patches/{{ patch.id }}/validate', {})" {% if patch.status != PatchStatus.APPROVED %}disabled{% endif %}>격리 검증</button>
    {% else %}
      <button data-testid="patch-generate" onclick="post('/api/events/{{ event.id }}/patches', {})" {% if not findings %}disabled{% endif %}>패치 생성</button>
    {% endif %}
  </section>
  <section data-testid="validation-panel">
    <h2>검증</h2>
    {% if patch and patch.validation_result %}
      {% for name, result in patch.validation_result.items() if name.endswith('_ok') or name == 'deployable' %}
        <p data-testid="validation-{{ name }}">{{ name }}: {{ 'SUCCESS' if result else 'FAILED' }}</p>
      {% endfor %}
    {% else %}<p>검증 결과가 없습니다.</p>{% endif %}
  </section>
  <section data-testid="deployment-panel">
    <h2>배포 및 롤백</h2>
    {% if patch %}<button data-testid="deploy-approve" onclick="post('/api/patches/{{ patch.id }}/deploy', {approved:true})" {% if patch.status != PatchStatus.VALIDATED %}disabled{% endif %}>배포 승인</button>{% endif %}
    {% if deployment %}
      <p data-testid="deployment-status">{{ deployment.status.value }}</p>
      <p>이전: {{ deployment.previous_image }} / 신규: {{ deployment.candidate_image }}</p>
      {% if deployment.error %}<p class="error">{{ deployment.error }}</p>{% endif %}
      <button data-testid="manual-rollback" onclick="post('/api/deployments/{{ deployment.id }}/rollback', {approved:true})" {% if deployment.status.value != 'COMPLETED' %}disabled{% endif %}>수동 롤백</button>
    {% else %}<p>배포 이력이 없습니다.</p>{% endif %}
  </section>
  <script>
    async function post(url, body) {
      const response = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
      if (!response.ok) { const data = await response.json(); alert(data.details || data.error); }
      location.reload();
    }
  </script>
</body>
</html>
"""


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8080)
