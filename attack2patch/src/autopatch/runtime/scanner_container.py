from __future__ import annotations

import shutil
from pathlib import Path
from uuid import uuid4

from autopatch.config import SandboxSettings
from autopatch.runtime.command import CommandResult, CommandRunner
from autopatch.runtime.sandbox import docker_security_flags


class DockerScannerRunner:
    """Execute a scanner image against a read-only target with explicit mounts."""

    def __init__(
        self,
        settings: SandboxSettings,
        *,
        runner: CommandRunner | None = None,
    ) -> None:
        self.settings = settings
        self.runner = runner or CommandRunner()

    def available(self) -> bool:
        return shutil.which(self.settings.docker_executable) is not None

    def run(
        self,
        *,
        image: str,
        argv: list[str],
        target: Path,
        timeout_seconds: int,
        network: str,
        mounts: list[tuple[Path, str, bool]] | None = None,
    ) -> CommandResult:
        target = target.resolve()
        name = f"autopatch-scanner-{uuid4().hex[:12]}"
        mount_flags = self._mount(target, "/src", True)
        for source, destination, readonly in mounts or []:
            mount_flags.extend(self._mount(source.resolve(), destination, readonly))
        command = [
            self.settings.docker_executable,
            "run",
            "--rm",
            "--name",
            name,
            "--network",
            network,
            *docker_security_flags(self.settings),
            *mount_flags,
            "--workdir",
            "/src",
            image,
            *argv,
        ]
        try:
            return self.runner.run(
                command,
                cwd=target,
                timeout_seconds=timeout_seconds,
            )
        finally:
            self.runner.run(
                [self.settings.docker_executable, "rm", "-f", name],
                cwd=target,
                timeout_seconds=self.settings.cleanup_timeout_seconds,
            )

    @staticmethod
    def _mount(source: Path, destination: str, readonly: bool) -> list[str]:
        if not source.exists():
            raise FileNotFoundError(source)
        if "," in str(source) or "\x00" in str(source):
            raise ValueError("Docker scanner mount source cannot contain comma or NUL")
        option = f"type=bind,source={source},target={destination}"
        if readonly:
            option += ",readonly"
        return ["--mount", option]
