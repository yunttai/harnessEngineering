from dataclasses import dataclass


@dataclass(frozen=True)
class BuildResult:
    image: str
    log: str


@dataclass(frozen=True)
class DeploymentVerification:
    health_ok: bool
    normal_request_ok: bool
    attack_test_ok: bool
    details: dict[str, object]

    @property
    def passed(self) -> bool:
        return self.health_ok and self.normal_request_ok and self.attack_test_ok

    def as_dict(self) -> dict[str, object]:
        return {
            "health_ok": self.health_ok,
            "normal_request_ok": self.normal_request_ok,
            "attack_test_ok": self.attack_test_ok,
            "passed": self.passed,
            "details": self.details,
        }
