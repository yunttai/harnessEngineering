import os
import subprocess
from pathlib import Path

from attack2patch.runtime.image_builder import DockerCommandError, validate_image_tag


class ComposeDeployer:
    """Control only the fixed demo-app service in the configured Compose project."""

    def __init__(self, compose_file: Path, project_name: str) -> None:
        self.compose_file = compose_file.resolve()
        if not self.compose_file.is_file():
            raise ValueError("configured Compose file does not exist")
        allowed = "abcdefghijklmnopqrstuvwxyz0123456789_-"
        if not project_name or any(character not in allowed for character in project_name):
            raise ValueError("invalid Compose project name")
        self.project_name = project_name

    def deploy(self, image: str) -> str:
        image = validate_image_tag(image)
        environment = os.environ.copy()
        environment["ATTACK2PATCH_DEMO_IMAGE"] = image
        command = self._compose_command()
        result = subprocess.run(
            command
            + [
                "--project-name",
                self.project_name,
                "-f",
                str(self.compose_file),
                "up",
                "-d",
                "--no-deps",
                "--force-recreate",
                "demo-app",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=90,
            env=environment,
        )
        output = (result.stdout + result.stderr)[-20_000:]
        if result.returncode != 0:
            raise DockerCommandError(f"Compose deployment failed: {output}")
        return output

    def rollback(self, image: str) -> str:
        return self.deploy(image)

    @staticmethod
    def _compose_command() -> list[str]:
        for command in (["docker", "compose"], ["docker-compose"]):
            try:
                result = subprocess.run(
                    [*command, "version"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            except OSError:
                continue
            if result.returncode == 0:
                return list(command)
        raise DockerCommandError("Docker Compose CLI is unavailable")
