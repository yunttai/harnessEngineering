from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
STATE_PATH = ROOT / ".autopatch" / "deployment.json"
TARGET_ID = hashlib.sha256(str(ROOT).encode("utf-8")).hexdigest()[:10]
CANARY_NAME = f"attack2patch-example-canary-{TARGET_ID}"
PRODUCTION_NAME = f"attack2patch-example-production-{TARGET_ID}"


def _run(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(  # noqa: S603 - fixed argv and locally derived identifiers
        argv,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )
    if completed.stdout:
        print(completed.stdout.rstrip())
    if completed.stderr:
        print(completed.stderr.rstrip(), file=sys.stderr)
    if check and completed.returncode != 0:
        raise RuntimeError(f"command failed ({completed.returncode}): {argv[0]} {argv[1]}")
    return completed


def _load() -> dict[str, Any]:
    if not STATE_PATH.is_file():
        raise RuntimeError("deployment state is missing; run staging first")
    value = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("deployment state is invalid")
    return value


def _save(value: dict[str, Any]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATE_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temporary, STATE_PATH)


def _remove(name: str) -> None:
    _run(["docker", "rm", "-f", name], check=False)


def _container_image(name: str) -> str | None:
    result = _run(
        ["docker", "inspect", "--format", "{{.Config.Image}}", name],
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else None


def _health(port: int, *, attempts: int = 30) -> None:
    url = f"http://127.0.0.1:{port}/health"
    last_error = "not attempted"
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=2) as response:  # noqa: S310
                payload = json.loads(response.read().decode("utf-8"))
            if response.status == 200 and payload.get("status") == "ok":
                print(f"health PASS {url}")
                return
            last_error = f"unexpected response: status={response.status} payload={payload!r}"
        except Exception as exc:  # readiness retry records the last concrete failure
            last_error = f"{type(exc).__name__}: {exc}"
        time.sleep(1)
    raise RuntimeError(f"health probe failed for {url}: {last_error}")


def _start(name: str, image: str, port: int) -> None:
    _run(
        [
            "docker",
            "run",
            "--detach",
            "--name",
            name,
            "--publish",
            f"127.0.0.1:{port}:8000",
            "--cpus",
            "1",
            "--memory",
            "256m",
            "--pids-limit",
            "128",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",  # noqa: S108 - hardened Docker tmpfs
            image,
        ]
    )
    _health(port)


def staging(production_port: int, canary_port: int) -> None:
    revision = _run(["git", "rev-parse", "HEAD"]).stdout.strip()
    if not revision:
        raise RuntimeError("git revision is unavailable")
    image = f"attack2patch-example:{revision[:12]}"
    previous = _container_image(PRODUCTION_NAME)
    _run(["docker", "build", "--tag", image, "."])
    _save(
        {
            "revision": revision,
            "candidate_image": image,
            "previous_image": previous,
            "production_port": production_port,
            "canary_port": canary_port,
            "promoted": False,
        }
    )
    print(f"staging PASS image={image} previous={previous or '-'}")


def canary() -> None:
    state = _load()
    _remove(CANARY_NAME)
    _start(CANARY_NAME, str(state["candidate_image"]), int(state["canary_port"]))
    print(f"canary PASS container={CANARY_NAME}")


def observe() -> None:
    state = _load()
    _health(int(state["canary_port"]), attempts=1)
    print(f"observation PASS revision={state['revision']}")


def promote() -> None:
    state = _load()
    _remove(PRODUCTION_NAME)
    _start(
        PRODUCTION_NAME,
        str(state["candidate_image"]),
        int(state["production_port"]),
    )
    _remove(CANARY_NAME)
    state["promoted"] = True
    _save(state)
    print(f"promotion PASS container={PRODUCTION_NAME}")


def rollback() -> None:
    state = _load()
    _remove(CANARY_NAME)
    _remove(PRODUCTION_NAME)
    previous = state.get("previous_image")
    if previous:
        _start(PRODUCTION_NAME, str(previous), int(state["production_port"]))
        print(f"rollback PASS restored={previous}")
    else:
        print("rollback PASS no previous release; candidate containers removed")
    state["promoted"] = False
    _save(state)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "phase",
        choices=("staging", "canary", "observe", "promote", "rollback"),
    )
    parser.add_argument("--production-port", type=int, default=18080)
    parser.add_argument("--canary-port", type=int, default=18081)
    args = parser.parse_args()
    if not 1024 <= args.production_port <= 65535:
        raise ValueError("production port must be between 1024 and 65535")
    if not 1024 <= args.canary_port <= 65535 or args.canary_port == args.production_port:
        raise ValueError("canary port must be distinct and between 1024 and 65535")
    if args.phase == "staging":
        staging(args.production_port, args.canary_port)
    elif args.phase == "canary":
        canary()
    elif args.phase == "observe":
        observe()
    elif args.phase == "promote":
        promote()
    else:
        rollback()


if __name__ == "__main__":
    main()
