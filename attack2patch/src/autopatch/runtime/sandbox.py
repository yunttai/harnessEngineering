from __future__ import annotations

import shutil
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Mapping
from urllib.parse import urlsplit
from uuid import uuid4

from autopatch.config import SandboxSettings
from autopatch.runtime.command import CommandResult, CommandRunner
from autopatch.types import ApplicationSpec


def prepare_container_workspace(workspace: Path) -> None:
    """Make only an ephemeral copied workspace writable across rootless Docker UIDs."""

    workspace = workspace.resolve()
    for path in [workspace, *workspace.rglob("*")]:
        if path.is_symlink():
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        path.chmod(mode | (0o777 if path.is_dir() else 0o666))


def _container_name(prefix: str) -> str:
    return f"autopatch-{prefix}-{uuid4().hex[:12]}"


def docker_security_flags(settings: SandboxSettings) -> list[str]:
    flags = [
        "--pull",
        "missing" if settings.allow_image_pull else "never",
        "--cpus",
        str(settings.cpu_limit),
        "--memory",
        f"{settings.memory_mb}m",
        "--pids-limit",
        str(settings.pids_limit),
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,size={settings.tmpfs_mb}m",
        "--tmpfs",
        f"/root/.cache:rw,noexec,nosuid,size={settings.tmpfs_mb}m",
        "--tmpfs",
        f"/root/.config:rw,noexec,nosuid,size={settings.tmpfs_mb}m",
    ]
    if settings.read_only_rootfs:
        flags.append("--read-only")
    if settings.user:
        flags.extend(["--user", settings.user])
    return flags


def _mount_flags(source: Path, workspace: Path) -> list[str]:
    for path in (source.resolve(), workspace.resolve()):
        if "," in str(path) or "\x00" in str(path):
            raise ValueError("Docker --mount source path cannot contain comma or NUL")
    return [
        "--mount",
        f"type=bind,source={source.resolve()},target=/source,readonly",
        "--mount",
        f"type=bind,source={workspace.resolve()},target=/workspace",
    ]


class DockerCommandRunner:
    """Run one command in a disposable, resource-limited Docker container."""

    def __init__(
        self,
        *,
        source: Path,
        workspace: Path,
        settings: SandboxSettings,
        runner: CommandRunner | None = None,
        executable_resolver: Callable[[str], str | None] | None = None,
    ) -> None:
        self.source = source.resolve()
        self.workspace = workspace.resolve()
        self.settings = settings
        self.runner = runner or CommandRunner()
        self._resolve = executable_resolver or shutil.which

    def available(self) -> bool:
        return self._resolve(self.settings.docker_executable) is not None

    def run(
        self,
        argv: list[str],
        *,
        cwd: Path,
        timeout_seconds: int,
        env: Mapping[str, str] | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        if env:
            raise ValueError("Docker sandbox environment injection is not supported")
        if input_text is not None:
            raise ValueError("Docker sandbox stdin injection is not supported")
        if not self.available():
            raise RuntimeError(
                f"Docker executable is unavailable: {self.settings.docker_executable}"
            )
        cwd = cwd.resolve()
        relative = cwd.relative_to(self.workspace)
        container_cwd = "/workspace"
        if relative.parts:
            container_cwd += "/" + "/".join(relative.parts)
        name = _container_name("verify")
        command = [
            self.settings.docker_executable,
            "run",
            "--rm",
            "--name",
            name,
            "--network",
            self.settings.network_mode,
            *docker_security_flags(self.settings),
            *_mount_flags(self.source, self.workspace),
            "--workdir",
            container_cwd,
            self.settings.image,
            *argv,
        ]
        try:
            return self.runner.run(
                command,
                cwd=self.workspace,
                timeout_seconds=timeout_seconds,
            )
        finally:
            self.runner.run(
                [self.settings.docker_executable, "rm", "-f", name],
                cwd=self.workspace,
                timeout_seconds=self.settings.cleanup_timeout_seconds,
            )


@dataclass(frozen=True, slots=True)
class ApplicationSession:
    target: str
    container_name: str
    network_name: str


class DockerApplicationRunner:
    """Launch an application with no external route and expose only a loopback port."""

    def __init__(
        self,
        *,
        source: Path,
        workspace: Path,
        settings: SandboxSettings,
        runner: CommandRunner | None = None,
        readiness_probe: Callable[[str, int, str], bool] | None = None,
    ) -> None:
        self.source = source.resolve()
        self.workspace = workspace.resolve()
        self.settings = settings
        self.runner = runner or CommandRunner()
        self._probe = readiness_probe or self._docker_probe

    @contextmanager
    def start(self, application: ApplicationSpec) -> Iterator[ApplicationSession]:
        network = _container_name("network")
        container = _container_name("app")
        docker = self.settings.docker_executable
        network_created = False
        container_started = False
        try:
            created = self.runner.run(
                [docker, "network", "create", "--internal", network],
                cwd=self.workspace,
                timeout_seconds=self.settings.cleanup_timeout_seconds,
            )
            if created.timed_out or created.exit_code != 0:
                raise RuntimeError(f"failed to create isolated Docker network: {created.stderr}")
            network_created = True

            command = [
                docker,
                "run",
                "--detach",
                "--name",
                container,
                "--network",
                network,
                *docker_security_flags(self.settings),
                *_mount_flags(self.source, self.workspace),
                "--workdir",
                "/workspace",
                self.settings.image,
                *application.command,
            ]
            started = self.runner.run(
                command,
                cwd=self.workspace,
                timeout_seconds=application.readiness.timeout_seconds,
            )
            if started.timed_out or started.exit_code != 0:
                raise RuntimeError(f"failed to start sandbox application: {started.stderr}")
            container_started = True

            target = f"http://{container}:{application.container_port}"
            self._wait_until_ready(target, application, network)
            yield ApplicationSession(target=target, container_name=container, network_name=network)
        finally:
            if container_started:
                self.runner.run(
                    [docker, "rm", "-f", container],
                    cwd=self.workspace,
                    timeout_seconds=self.settings.cleanup_timeout_seconds,
                )
            if network_created:
                self.runner.run(
                    [docker, "network", "rm", network],
                    cwd=self.workspace,
                    timeout_seconds=self.settings.cleanup_timeout_seconds,
                )

    def _wait_until_ready(
        self,
        target: str,
        application: ApplicationSpec,
        network: str,
    ) -> None:
        probe = application.readiness
        deadline = time.monotonic() + probe.timeout_seconds
        url = target + probe.path
        while True:
            if self._probe(url, probe.expected_status, network):
                return
            if time.monotonic() >= deadline:
                raise TimeoutError(f"application readiness probe timed out: {url}")
            time.sleep(probe.interval_ms / 1000)

    def _docker_probe(self, url: str, expected_status: int, network: str) -> bool:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "http"
            or parsed.hostname is None
            or not parsed.hostname.startswith("autopatch-app-")
            or not network.startswith("autopatch-network-")
        ):
            return False
        name = _container_name("probe")
        code = (
            "import sys,urllib.request; "
            f"response=urllib.request.urlopen({url!r}, timeout=2); "
            f"sys.exit(0 if response.status == {expected_status} else 1)"
        )
        try:
            result = self.runner.run(
                [
                    self.settings.docker_executable,
                    "run",
                    "--rm",
                    "--name",
                    name,
                    "--network",
                    network,
                    *docker_security_flags(self.settings),
                    self.settings.image,
                    "python",
                    "-c",
                    code,
                ],
                cwd=self.workspace,
                timeout_seconds=5,
            )
            return not result.timed_out and result.exit_code == 0
        finally:
            self.runner.run(
                [self.settings.docker_executable, "rm", "-f", name],
                cwd=self.workspace,
                timeout_seconds=self.settings.cleanup_timeout_seconds,
            )
