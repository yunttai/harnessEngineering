from dataclasses import dataclass


@dataclass(frozen=True)
class ValidationResult:
    syntax_ok: bool
    regression_tests_ok: bool
    attack_test_ok: bool
    rescan_ok: bool

    @property
    def deployable(self) -> bool:
        return all(
            (self.syntax_ok, self.regression_tests_ok, self.attack_test_ok, self.rescan_ok)
        )
