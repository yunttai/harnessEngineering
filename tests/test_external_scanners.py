from __future__ import annotations

from pathlib import Path

from autopatch.runtime.external_scanners import parse_gitleaks, parse_sarif, parse_trivy


def test_sarif_trivy_and_gitleaks_normalize_to_finding(tmp_path: Path) -> None:
    sarif = parse_sarif(
        tmp_path,
        {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeQL",
                            "rules": [
                                {
                                    "id": "py/sql-injection",
                                    "properties": {"tags": ["security", "CWE-089"]},
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "py/sql-injection",
                            "level": "error",
                            "message": {"text": "SQL query depends on user input"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/app.py"},
                                        "region": {"startLine": 12, "endLine": 12},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        },
    )
    trivy = parse_trivy(
        tmp_path,
        {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Class": "lang-pkgs",
                    "Type": "pip",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-0001",
                            "PkgName": "demo",
                            "InstalledVersion": "1.0",
                            "FixedVersion": "1.1",
                            "Severity": "HIGH",
                            "CweIDs": ["CWE-79"],
                        }
                    ],
                }
            ]
        },
    )
    gitleaks = parse_gitleaks(
        tmp_path,
        [
            {
                "RuleID": "generic-api-key",
                "Description": "Generic API key",
                "File": "src/settings.py",
                "StartLine": 4,
                "EndLine": 4,
                "Secret": "must-not-be-retained",
                "Fingerprint": "fixture",
            }
        ],
    )

    assert sarif[0].cwe == "CWE-89"
    assert sarif[0].scanner == "CodeQL"
    assert trivy[0].scanner == "trivy"
    assert trivy[0].metadata["fixed_version"] == "1.1"
    assert gitleaks[0].cwe == "CWE-798"
    assert "must-not-be-retained" not in gitleaks[0].model_dump_json()
