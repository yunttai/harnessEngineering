import re
import subprocess
from pathlib import Path

from attack2patch.types.runtime_result import BuildResult


IMAGE_TAG_PATTERN = re.compile(r"^attack2patch-demo:[a-z0-9][a-z0-9._-]{0,63}$")


class DockerCommandError(RuntimeError):
    pass


def validate_image_tag(image: str) -> str:
    if not IMAGE_TAG_PATTERN.fullmatch(image):
        raise ValueError("image tag is outside the Attack2Patch allowlist")
    return image


class DockerImageBuilder:
    """Build a validated candidate using argument arrays, never a shell string."""

    def build(self, build_context: Path, image: str) -> BuildResult:
        image = validate_image_tag(image)
        build_context = build_context.resolve()
        if not build_context.is_dir() or not (build_context / "Dockerfile").is_file():
            raise ValueError("candidate build context is invalid")
        result = subprocess.run(
            ["docker", "build", "--tag", image, str(build_context)],
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
        log = (result.stdout + result.stderr)[-20_000:]
        if result.returncode != 0:
            raise DockerCommandError(f"image build failed: {log}")
        return BuildResult(image=image, log=log)
