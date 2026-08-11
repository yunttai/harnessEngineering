from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Annotated, Literal, cast

import typer

from autopatch.config import load_settings
from autopatch.runtime.factory import (
    build_artifact_store,
    build_detection_service,
    build_orchestrator,
    build_publishing_service,
)
from autopatch.service import PublishOptions
from autopatch.types import FindingStatus, RunState
from autopatch.ui.common import validate_target

app = typer.Typer(
    name="attack2patch",
    help="Attack2Patch verification-driven secure auto-patching harness",
    no_args_is_help=True,
)


def _config_path(value: Path | None) -> Path:
    return (value or Path(os.getenv("AUTOPATCH_CONFIG", "config/harness.yaml"))).resolve()


@app.command()
def scan(
    target: Annotated[Path, typer.Argument(help="Authorized local source repository")],
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Harness YAML configuration"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print machine-readable JSON"),
    ] = False,
) -> None:
    """Run detection and Finding normalization without generating patches."""
    config_path = _config_path(config)
    settings = load_settings(config_path)
    resolved = validate_target(target, settings)
    detection = build_detection_service(settings=settings, config_path=config_path)
    result = detection.scan(resolved)

    payload = {
        "target": str(resolved),
        "findings": [finding.model_dump(mode="json") for finding in result.findings],
        "errors": result.errors,
        "skipped": result.skipped,
        "executed": result.executed,
    }
    if json_output:
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        typer.echo(f"target: {resolved}")
        typer.echo(f"findings: {len(result.findings)}")
        typer.echo(f"executed_scanners: {', '.join(result.executed) or '-'}")
        for finding in result.findings:
            typer.echo(
                f"- {finding.finding_id} {finding.severity} {finding.cwe} "
                f"{finding.file}:{finding.line} {finding.message}"
            )
        for error in result.errors:
            typer.echo(f"ERROR: {error}", err=True)
        for skipped in result.skipped:
            typer.echo(f"SKIPPED: {skipped}")
    if result.errors:
        raise typer.Exit(code=2)


@app.command()
def run(
    target: Annotated[Path, typer.Argument(help="Authorized local source repository")],
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Harness YAML configuration"),
    ] = None,
    apply: Annotated[
        bool,
        typer.Option(
            "--apply",
            help="Apply the highest-ranked VERIFIED candidate to the original target",
        ),
    ] = False,
    execute_tests: Annotated[
        bool,
        typer.Option(
            "--execute-tests",
            help="Execute the target project's test suite; only for trusted targets",
        ),
    ] = False,
    execute_security_tests: Annotated[
        bool,
        typer.Option(
            "--execute-security-tests",
            help="Execute autopatch-security-tests.yaml commands; only for trusted targets",
        ),
    ] = False,
    llm_cli: Annotated[
        str | None,
        typer.Option(
            "--llm-cli",
            help="Select an authenticated local LLM CLI: codex, opencode, or claude",
        ),
    ] = None,
    no_llm: Annotated[
        bool,
        typer.Option(
            "--no-llm",
            help="Disable the default LLM CLI and use deterministic providers only",
        ),
    ] = False,
    llm_model: Annotated[
        str | None,
        typer.Option(
            "--llm-model",
            help="Optional model override passed to the selected LLM CLI",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print complete RunReport JSON"),
    ] = False,
) -> None:
    """Execute detection, analysis, patch generation and verification."""
    config_path = _config_path(config)
    settings = load_settings(config_path)
    if no_llm and llm_cli is not None:
        raise typer.BadParameter("--no-llm cannot be combined with --llm-cli")
    if llm_cli is not None:
        normalized = llm_cli.strip().lower()
        if normalized not in {"codex", "opencode", "claude"}:
            raise typer.BadParameter("--llm-cli must be codex, opencode, or claude")
        settings.llm.enabled = True
        settings.llm.provider = cast(
            Literal["codex", "opencode", "claude"],
            normalized,
        )
    if no_llm:
        settings.llm.enabled = False
    if llm_model is not None:
        if not settings.llm.enabled:
            raise typer.BadParameter("--llm-model requires --llm-cli or llm.enabled=true")
        settings.llm.model = llm_model.strip() or None
    resolved = validate_target(target, settings)

    orchestrator = build_orchestrator(
        settings=settings,
        config_path=config_path,
        execute_tests=execute_tests,
        execute_security_tests=execute_security_tests,
    )
    report = orchestrator.run(resolved, apply=apply)

    if json_output:
        typer.echo(report.model_dump_json(indent=2))
    else:
        typer.echo(f"run_id: {report.run_id}")
        typer.echo(f"state: {report.state}")
        typer.echo(f"target: {report.target}")
        typer.echo(f"artifact_dir: {report.artifact_dir}")
        typer.echo(f"findings: {len(report.findings)}")
        for outcome in report.outcomes:
            selected = outcome.selected_candidate_id or "-"
            score = "-"
            if outcome.evaluations and outcome.selected_candidate_id:
                selected_evaluation = next(
                    (
                        item
                        for item in outcome.evaluations
                        if item.candidate.candidate_id == outcome.selected_candidate_id
                    ),
                    None,
                )
                if selected_evaluation:
                    score = str(selected_evaluation.verification.score.total)
            typer.echo(
                f"- {outcome.finding.finding_id} status={outcome.status} "
                f"selected={selected} score={score} applied={outcome.applied}"
            )
            if outcome.reason:
                typer.echo(f"  reason: {outcome.reason}")

    failed = all(
        outcome.status in {FindingStatus.FAILED, FindingStatus.NEEDS_HUMAN_REVIEW}
        for outcome in report.outcomes
    ) and bool(report.outcomes)
    if report.scanner_errors:
        raise typer.Exit(code=2)
    if failed:
        raise typer.Exit(code=3)


@app.command("validate-config")
def validate_config(
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Harness YAML configuration"),
    ] = None,
) -> None:
    """Parse the configuration and enforce cross-field policy constraints."""
    config_path = _config_path(config)
    settings = load_settings(config_path)
    typer.echo(f"valid: {config_path}")
    typer.echo(f"project_name: {settings.project_name}")
    typer.echo(f"scanners: {', '.join(item.name for item in settings.detection.scanners)}")
    typer.echo(
        f"llm_cli: {settings.llm.provider} "
        f"({'enabled' if settings.llm.enabled else 'disabled'})"
    )


@app.command("publish")
def publish(
    target: Annotated[Path, typer.Argument(help="Authorized local Git repository")],
    run_id: Annotated[str, typer.Argument(help="VERIFIED Attack2Patch run id")],
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Harness YAML configuration"),
    ] = None,
    commit: Annotated[
        bool,
        typer.Option("--commit", help="Commit only the selected candidate files"),
    ] = False,
    push: Annotated[
        bool,
        typer.Option("--push", help="Push the committed branch to the configured remote"),
    ] = False,
    pull_request: Annotated[
        bool,
        typer.Option("--pull-request", help="Create a draft PR through the configured GitHub App"),
    ] = False,
    branch: Annotated[
        str | None,
        typer.Option("--branch", help="Override the generated security branch name"),
    ] = None,
) -> None:
    """Apply and publish a previously VERIFIED run through independent gates."""
    config_path = _config_path(config)
    settings = load_settings(config_path)
    resolved = validate_target(target, settings)
    store = build_artifact_store(settings=settings)
    report = store.read_run(run_id)
    if Path(report.target).resolve() != resolved:
        raise typer.BadParameter("run target does not match the requested repository")
    service = build_publishing_service(settings=settings)
    result = service.publish(
        resolved,
        report,
        PublishOptions(
            create_commit=commit,
            push_branch=push,
            create_pull_request=pull_request,
            branch=branch,
        ),
    )
    for outcome in report.outcomes:
        if outcome.selected_candidate_id:
            outcome.applied = True
            outcome.status = FindingStatus.APPLIED
            outcome.finding.status = FindingStatus.APPLIED
    report.pull_request = result.pull_request
    final_state = RunState.PR_CREATED if result.pull_request else RunState.APPLIED
    report.transition(
        final_state,
        "verified patch published",
        branch=result.branch,
        base_sha=result.base_sha,
        commit_sha=result.commit_sha,
        pushed=result.pushed,
    )
    store.write_run(report)
    typer.echo(f"state: {report.state}")
    typer.echo(f"branch: {result.branch}")
    typer.echo(f"commit: {result.commit_sha or '-'}")
    typer.echo(f"pull_request: {result.pull_request.url if result.pull_request else '-'}")


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Bind address")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="TCP port", min=1, max=65535)] = 8000,
    reload: Annotated[bool, typer.Option(help="Development reload")] = False,
) -> None:
    """Start the local FastAPI boundary."""
    import uvicorn

    uvicorn.run("autopatch.ui.api:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    app()
