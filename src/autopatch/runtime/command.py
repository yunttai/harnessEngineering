from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


@dataclass(slots=True)
class CommandResult:
    argv: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False


class CommandRunner:
    def __init__(self, max_output_chars: int = 20_000) -> None:
        self.max_output_chars = max_output_chars

    def run(
        self,
        argv: list[str],
        *,
        cwd: Path,
        timeout_seconds: int,
        env: Mapping[str, str] | None = None,
    ) -> CommandResult:
        if not argv or not argv[0].strip():
            raise ValueError("argv must contain an executable")
        if any("\x00" in item for item in argv):
            raise ValueError("argv contains NUL")
        if not cwd.is_dir():
            raise NotADirectoryError(cwd)

        safe_env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", str(cwd)),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "LC_ALL": os.environ.get("LC_ALL", ""),
            "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
        }
        # Windows process and socket initialization depends on these variables.
        # Keep the allowlist explicit instead of forwarding the full environment.
        for key in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP"):
            value = os.environ.get(key)
            if value:
                safe_env[key] = value
        if env:
            safe_env.update({str(key): str(value) for key, value in env.items()})

        started = time.monotonic()
        try:
            completed = subprocess.run(
                argv,
                cwd=cwd,
                env=safe_env,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
                shell=False,
            )
            duration = int((time.monotonic() - started) * 1000)
            return CommandResult(
                argv=list(argv),
                exit_code=completed.returncode,
                stdout=self._truncate(completed.stdout),
                stderr=self._truncate(completed.stderr),
                duration_ms=duration,
            )
        except subprocess.TimeoutExpired as exc:
            duration = int((time.monotonic() - started) * 1000)
            stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return CommandResult(
                argv=list(argv),
                exit_code=None,
                stdout=self._truncate(stdout),
                stderr=self._truncate(stderr),
                duration_ms=duration,
                timed_out=True,
            )

    def _truncate(self, value: str) -> str:
        if len(value) <= self.max_output_chars:
            return value
        return value[: self.max_output_chars] + "\n...[truncated]"
