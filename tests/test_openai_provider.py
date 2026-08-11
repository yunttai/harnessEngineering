from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from autopatch.config import LlmSettings
from autopatch.runtime.builtin_scanner import BuiltinPythonScanner
from autopatch.runtime.openai_provider import OpenAIResponsesProvider
from autopatch.service.analysis import RuleBasedAnalyzer


class _Response:
    status_code = 200

    def __init__(self, output: dict[str, Any]) -> None:
        self.output = output

    def json(self) -> dict[str, Any]:
        return {
            "id": "resp_fixture",
            "status": "completed",
            "output": [
                {
                    "type": "message",
                    "content": [
                        {"type": "output_text", "text": json.dumps(self.output)}
                    ],
                }
            ],
        }


class _Client:
    def __init__(self, response: _Response) -> None:
        self.response = response
        self.requests: list[dict[str, Any]] = []

    def post(self, url: str, *, headers: dict[str, str], json: dict[str, Any]) -> _Response:
        self.requests.append({"url": url, "headers": headers, "json": json})
        return self.response


def test_openai_patch_provider_uses_strict_schema_and_materializes_edits(
    vulnerable_project: Path,
    monkeypatch,
) -> None:
    finding = next(
        item for item in BuiltinPythonScanner().scan(vulnerable_project) if item.cwe == "CWE-89"
    )
    analysis = RuleBasedAnalyzer().analyze(vulnerable_project, finding)
    client = _Client(
        _Response(
            {
                "candidates": [
                    {
                        "title": "Parameterize query",
                        "description": "Separate SQL structure and value",
                        "rationale": "Use DB-API parameters",
                        "expected_security_effect": "Input cannot alter SQL syntax",
                        "edits": [
                            {
                                "file": "app.py",
                                "start_line": 25,
                                "end_line": 25,
                                "replacement": '    query = "SELECT * FROM users WHERE id=%s"',
                            },
                            {
                                "file": "app.py",
                                "start_line": 26,
                                "end_line": 26,
                                "replacement": "    cursor.execute(query, (user_id,))",
                            },
                        ],
                    }
                ]
            }
        )
    )
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    provider = OpenAIResponsesProvider(LlmSettings(enabled=True), client=client)

    candidates = provider.generate(vulnerable_project, finding, analysis)

    assert len(candidates) == 1
    assert candidates[0].provider == "openai-responses"
    assert "cursor.execute(query, (user_id,))" in candidates[0].unified_diff
    request = client.requests[0]["json"]
    assert request["store"] is False
    assert request["text"]["format"]["type"] == "json_schema"
    assert request["text"]["format"]["strict"] is True
    assert request["text"]["format"]["schema"]["additionalProperties"] is False


def test_openai_provider_rejects_refusal(vulnerable_project: Path, monkeypatch) -> None:
    class _RefusalResponse(_Response):
        def json(self) -> dict[str, Any]:
            return {
                "id": "resp_refusal",
                "status": "completed",
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "refusal", "refusal": "cannot comply"}],
                    }
                ],
            }

    finding = BuiltinPythonScanner().scan(vulnerable_project)[0]
    analysis = RuleBasedAnalyzer().analyze(vulnerable_project, finding)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    provider = OpenAIResponsesProvider(
        LlmSettings(enabled=True),
        client=_Client(_RefusalResponse({})),
    )
    try:
        provider.generate(vulnerable_project, finding, analysis)
    except RuntimeError as exc:
        assert "refused" in str(exc)
    else:
        raise AssertionError("refusal must fail closed")
