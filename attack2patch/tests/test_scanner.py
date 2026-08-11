from __future__ import annotations

from pathlib import Path

from autopatch.runtime.builtin_scanner import BuiltinPythonScanner


def test_builtin_scanner_detects_cwe89(vulnerable_project: Path) -> None:
    findings = BuiltinPythonScanner().scan(vulnerable_project)
    sql = [finding for finding in findings if finding.cwe == "CWE-89"]
    assert len(sql) == 1
    finding = sql[0]
    assert finding.file == "app.py"
    assert finding.function == "get_user"
    assert finding.source == "request.args.get"
    assert finding.sink == "cursor.execute"
    assert finding.metadata["query_variable"] == "query"


def test_scanner_fingerprint_is_stable(vulnerable_project: Path) -> None:
    scanner = BuiltinPythonScanner()
    first = scanner.scan(vulnerable_project)
    second = scanner.scan(vulnerable_project)
    assert [item.fingerprint for item in first] == [item.fingerprint for item in second]
