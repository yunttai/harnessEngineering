import json
import time
from urllib.parse import urlencode
from urllib.request import urlopen

from attack2patch.types.attack_payloads import MVP_SQL_INJECTION_PAYLOADS
from attack2patch.types.runtime_result import DeploymentVerification


def is_healthy(url: str, timeout_seconds: float = 3.0) -> bool:
    try:
        with urlopen(url, timeout=timeout_seconds) as response:  # noqa: S310 - configured URL
            return response.status == 200
    except OSError:
        return False


class PostDeploymentVerifier:
    def __init__(
        self,
        base_url: str,
        timeout_seconds: float = 5.0,
        startup_timeout_seconds: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.startup_timeout_seconds = startup_timeout_seconds

    def verify(self) -> DeploymentVerification:
        health_ok = self._wait_until_healthy()
        normal_ok = False
        attack_ok = False
        details: dict[str, object] = {}
        if not health_ok:
            details["request_error"] = "healthcheck readiness timeout"
            return DeploymentVerification(False, False, False, details)
        try:
            normal_body = self._get_users("alice")
            normal_ok = normal_body == [{"id": 1, "name": "alice"}]
            details["normal_response"] = normal_body
            attack_results: dict[str, object] = {}
            attack_ok = True
            for payload in MVP_SQL_INJECTION_PAYLOADS:
                body = self._get_users(payload)
                blocked = body == []
                attack_results[payload] = {"blocked": blocked, "body": body}
                attack_ok = attack_ok and blocked
            details["attack_responses"] = attack_results
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            details["request_error"] = f"{type(exc).__name__}: {exc}"
        return DeploymentVerification(health_ok, normal_ok, attack_ok, details)

    def _wait_until_healthy(self) -> bool:
        deadline = time.monotonic() + self.startup_timeout_seconds
        while time.monotonic() < deadline:
            if is_healthy(f"{self.base_url}/health", self.timeout_seconds):
                return True
            time.sleep(0.25)
        return False

    def _get_users(self, name: str) -> object:
        query = urlencode({"name": name})
        with urlopen(
            f"{self.base_url}/api/users?{query}", timeout=self.timeout_seconds
        ) as response:  # noqa: S310 - URL is validated configuration, not request input.
            if response.status != 200:
                raise OSError(f"unexpected status {response.status}")
            return json.loads(response.read().decode("utf-8"))
