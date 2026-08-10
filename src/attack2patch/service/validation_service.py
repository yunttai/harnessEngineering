from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class ValidationResult:
    syntax_ok: bool
    unit_tests_ok: bool
    normal_request_ok: bool
    attack_test_ok: bool
    rescan_ok: bool
    details: dict[str, str]

    @property
    def regression_tests_ok(self) -> bool:
        return self.unit_tests_ok and self.normal_request_ok

    @property
    def deployable(self) -> bool:
        return all(
            (
                self.syntax_ok,
                self.unit_tests_ok,
                self.normal_request_ok,
                self.attack_test_ok,
                self.rescan_ok,
            )
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "syntax_ok": self.syntax_ok,
            "unit_tests_ok": self.unit_tests_ok,
            "normal_request_ok": self.normal_request_ok,
            "attack_test_ok": self.attack_test_ok,
            "rescan_ok": self.rescan_ok,
            "deployable": self.deployable,
            "details": self.details,
        }


class CandidateValidator(Protocol):
    def __call__(self, workspace: Path, target_file: Path) -> ValidationResult: ...
