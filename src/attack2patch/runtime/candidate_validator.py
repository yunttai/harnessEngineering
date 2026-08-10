import importlib.util
import json
import sys
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from attack2patch.runtime.test_runner import run_pytest
from attack2patch.service.code_scanner import scan_file
from attack2patch.service.validation_service import ValidationResult
from attack2patch.types.attack_payloads import MVP_SQL_INJECTION_PAYLOADS


def validate_workspace(workspace: Path, target_file: Path) -> ValidationResult:
    workspace = workspace.resolve()
    target_file = target_file.resolve()
    if workspace not in target_file.parents:
        raise ValueError("validation target escapes workspace")

    syntax_ok, syntax_detail = _syntax_check(workspace)
    unit_tests_ok, unit_detail = _unit_tests(workspace / "demo-app")
    normal_ok = False
    attack_ok = False
    request_detail = "not run because syntax validation failed"
    attack_detail = request_detail
    if syntax_ok:
        try:
            with _load_demo_app(target_file) as module:
                client = module.app.test_client()
                normal_response = client.get("/api/users", query_string={"name": "alice"})
                normal_body = normal_response.get_json()
                normal_ok = normal_response.status_code == 200 and normal_body == [
                    {"id": 1, "name": "alice"}
                ]
                request_detail = f"status={normal_response.status_code} body={normal_body!r}"
                attack_results: dict[str, object] = {}
                attack_ok = True
                for payload in MVP_SQL_INJECTION_PAYLOADS:
                    response = client.get("/api/users", query_string={"name": payload})
                    body = response.get_json()
                    blocked = response.status_code == 200 and body == []
                    attack_results[payload] = {"status": response.status_code, "blocked": blocked}
                    attack_ok = attack_ok and blocked
                attack_detail = json.dumps(attack_results, sort_keys=True)
        except Exception as exc:  # Validation is intentionally fail-closed.
            request_detail = f"candidate execution failed: {type(exc).__name__}: {exc}"
            attack_detail = request_detail

    remaining_findings = scan_file(target_file) if syntax_ok else [-1]
    rescan_ok = not remaining_findings
    return ValidationResult(
        syntax_ok=syntax_ok,
        unit_tests_ok=unit_tests_ok,
        normal_request_ok=normal_ok,
        attack_test_ok=attack_ok,
        rescan_ok=rescan_ok,
        details={
            "syntax": syntax_detail,
            "unit_tests": unit_detail,
            "normal_request": request_detail,
            "attack_test": attack_detail,
            "rescan": f"remaining lines: {remaining_findings}",
        },
    )


def _syntax_check(workspace: Path) -> tuple[bool, str]:
    try:
        checked = 0
        for path in workspace.rglob("*.py"):
            compile(path.read_text(encoding="utf-8"), str(path), "exec")
            checked += 1
        return True, f"compiled {checked} Python files"
    except (OSError, SyntaxError) as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _unit_tests(application_root: Path) -> tuple[bool, str]:
    try:
        result = run_pytest(application_root, marker_expression="not baseline_vulnerable")
        output = (result.stdout + result.stderr).strip()
        return result.returncode == 0, output[-4000:]
    except (OSError, TimeoutError) as exc:
        return False, f"{type(exc).__name__}: {exc}"


@contextmanager
def _load_demo_app(path: Path):
    module_name = f"attack2patch_candidate_{uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if not spec or not spec.loader:
        raise RuntimeError("cannot load candidate app")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        database_path = path.parent / "validation.db"
        module.DATABASE = str(database_path)
        module.initialize_database()
        yield module
    finally:
        sys.modules.pop(module_name, None)
