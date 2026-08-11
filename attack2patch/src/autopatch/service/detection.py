from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from autopatch.providers import Scanner
from autopatch.types import Finding


@dataclass(slots=True)
class DetectionResult:
    findings: list[Finding]
    errors: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    executed: list[str] = field(default_factory=list)


class DetectionService:
    def __init__(self, scanners: list[Scanner], fail_on_required_error: bool = True) -> None:
        self.scanners = scanners
        self.fail_on_required_error = fail_on_required_error

    def scan(self, target: Path) -> DetectionResult:
        merged: dict[str, Finding] = {}
        errors: list[str] = []
        skipped: list[str] = []
        executed: list[str] = []

        for scanner in self.scanners:
            if not scanner.available():
                message = f"{scanner.name}: unavailable"
                if scanner.required and self.fail_on_required_error:
                    errors.append(message)
                else:
                    skipped.append(message)
                continue

            try:
                results = scanner.scan(target)
            except Exception as exc:  # provider boundary; preserve failure as evidence
                message = f"{scanner.name}: {type(exc).__name__}: {exc}"
                if scanner.required and self.fail_on_required_error:
                    errors.append(message)
                else:
                    skipped.append(message)
                continue

            executed.append(scanner.name)
            for finding in results:
                existing = merged.get(finding.fingerprint)
                if existing is None:
                    existing = next(
                        (
                            item
                            for item in merged.values()
                            if item.scanner != finding.scanner
                            and item.cwe == finding.cwe
                            and item.file == finding.file
                            and item.line == finding.line
                        ),
                        None,
                    )
                if existing is None:
                    merged[finding.fingerprint] = finding
                    continue
                existing.evidence.extend(finding.evidence)
                scanners = set(existing.metadata.get("corroborating_scanners", []))
                scanners.add(existing.scanner)
                scanners.add(finding.scanner)
                existing.metadata["corroborating_scanners"] = sorted(scanners)

        findings = sorted(
            merged.values(),
            key=lambda item: (item.file, item.line, item.cwe, item.finding_id),
        )
        return DetectionResult(
            findings=findings,
            errors=errors,
            skipped=skipped,
            executed=executed,
        )
