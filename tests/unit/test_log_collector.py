from attack2patch.runtime.log_collector import REDACTED, HttpLogRecord, parse_access_log_line


def test_parses_and_decodes_supported_access_log_line():
    record = parse_access_log_line(
        "2026-08-10T10:01:00Z GET "
        "/api/users?name=%27%20OR%201%3D1-- 127.0.0.1 200"
    )
    assert record.path == "/api/users"
    assert record.parameters == {"name": "' OR 1=1--"}


def test_redacts_sensitive_values_before_serialization():
    record = HttpLogRecord(
        timestamp="2026-08-10T10:01:00Z",
        method="POST",
        path="/api/users",
        parameters={"name": "alice", "password": "do-not-store"},
        headers={"Authorization": "Bearer secret", "X-Trace": "safe"},
        source_ip="127.0.0.1",
        status_code=200,
    )
    assert record.sanitized_parameters()["password"] == REDACTED
    assert record.sanitized_headers()["Authorization"] == REDACTED
    assert "do-not-store" not in record.sanitized_payload()
    assert record.sanitized_headers()["X-Trace"] == "safe"


def test_rejects_unknown_log_fields():
    try:
        HttpLogRecord.model_validate(
            {
                "timestamp": "2026-08-10T10:01:00Z",
                "method": "GET",
                "path": "/api/users",
                "source_ip": "127.0.0.1",
                "status_code": 200,
                "unexpected": "field",
            }
        )
    except ValueError:
        pass
    else:
        raise AssertionError("unknown external fields must be rejected")
