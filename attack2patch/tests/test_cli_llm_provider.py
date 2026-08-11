from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from autopatch.config import LlmSettings
from autopatch.runtime.builtin_scanner import BuiltinPythonScanner
from autopatch.runtime.cli_llm_provider import CliLlmProvider
from autopatch.runtime.command import CommandResult, CommandRunner
from autopatch.service.analysis import RuleBasedAnalyzer


def _patch_output() -> dict[str, Any]:
    return {
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


class _FakeCliRunner:
    def __init__(self, provider: str, output: dict[str, Any] | None = None) -> None:
        self.provider = provider
        self.output = output or _patch_output()
        self.calls: list[dict[str, Any]] = []

    def run(
        self,
        argv: list[str],
        *,
        cwd: Path,
        timeout_seconds: int,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        call: dict[str, Any] = {
            "argv": argv,
            "cwd": cwd,
            "timeout_seconds": timeout_seconds,
            "env": env or {},
            "input_text": input_text,
        }
        if self.provider == "opencode":
            prompt_path = Path(argv[argv.index("--file") + 1])
            call["attached_prompt"] = prompt_path.read_text(encoding="utf-8")
        self.calls.append(call)

        if self.provider == "codex":
            output_path = Path(argv[argv.index("--output-last-message") + 1])
            output_path.write_text(json.dumps(self.output), encoding="utf-8")
            stdout = ""
        elif self.provider == "claude":
            stdout = json.dumps(
                {
                    "type": "result",
                    "session_id": "claude-session",
                    "structured_output": self.output,
                }
            )
        else:
            stdout = "\n".join(
                [
                    json.dumps({"type": "step_start", "sessionID": "open-session"}),
                    json.dumps(
                        {
                            "type": "text",
                            "sessionID": "open-session",
                            "part": {
                                "type": "text",
                                "text": json.dumps(self.output),
                            },
                        }
                    ),
                ]
            )
        return CommandResult(
            argv=argv,
            exit_code=0,
            stdout=stdout,
            stderr="",
            duration_ms=7,
        )


@pytest.mark.parametrize("cli_name", ["codex", "opencode", "claude"])
def test_cli_patch_providers_materialize_strict_candidates(
    cli_name: str,
    vulnerable_project: Path,
) -> None:
    finding = next(
        item for item in BuiltinPythonScanner().scan(vulnerable_project) if item.cwe == "CWE-89"
    )
    analysis = RuleBasedAnalyzer().analyze(vulnerable_project, finding)
    runner = _FakeCliRunner(cli_name)
    provider = CliLlmProvider(
        LlmSettings(enabled=True, provider=cli_name, model="fixture-model"),
        runner=runner,  # type: ignore[arg-type]
        executable_resolver=lambda value: f"/resolved/{value}",
    )

    candidates = provider.generate(vulnerable_project, finding, analysis)

    assert len(candidates) == 1
    assert candidates[0].provider == f"{cli_name}-cli"
    assert "cursor.execute(query, (user_id,))" in candidates[0].unified_diff
    assert candidates[0].metadata["provider_invocation_id"].startswith(f"{cli_name}-cli:")
    call = runner.calls[0]
    assert call["cwd"] != vulnerable_project
    assert call["timeout_seconds"] == 120
    assert "fixture-model" in call["argv"]

    if cli_name == "codex":
        assert "--output-schema" in call["argv"]
        assert "--sandbox" in call["argv"]
        assert "read-only" in call["argv"]
        assert "untrusted repository data" in call["input_text"]
    elif cli_name == "claude":
        assert "--json-schema" in call["argv"]
        assert call["argv"][call["argv"].index("--tools") + 1] == ""
        assert "untrusted repository data" in call["input_text"]
    else:
        assert call["env"]["OPENCODE_CONFIG_CONTENT"] == (
            '{"permission":"deny","share":"disabled"}'
        )
        assert "untrusted repository data" in call["attached_prompt"]


def test_cli_provider_rejects_non_structured_output(vulnerable_project: Path) -> None:
    class _InvalidRunner(_FakeCliRunner):
        def run(self, *args: Any, **kwargs: Any) -> CommandResult:
            result = super().run(*args, **kwargs)
            result.stdout = json.dumps(
                {
                    "type": "text",
                    "part": {"type": "text", "text": "not structured JSON"},
                }
            )
            return result

    finding = BuiltinPythonScanner().scan(vulnerable_project)[0]
    analysis = RuleBasedAnalyzer().analyze(vulnerable_project, finding)
    provider = CliLlmProvider(
        LlmSettings(enabled=True, provider="opencode"),
        runner=_InvalidRunner("opencode"),  # type: ignore[arg-type]
        executable_resolver=lambda value: value,
    )

    with pytest.raises(ValueError, match="structured output"):
        provider.generate(vulnerable_project, finding, analysis)


def test_command_runner_passes_prompt_over_stdin(tmp_path: Path) -> None:
    result = CommandRunner().run(
        [sys.executable, "-c", "import sys; print(sys.stdin.read())"],
        cwd=tmp_path,
        timeout_seconds=10,
        input_text="structured prompt",
    )

    assert result.exit_code == 0
    assert result.stdout.strip() == "structured prompt"
