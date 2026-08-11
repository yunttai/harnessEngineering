from __future__ import annotations

from pathlib import Path

from autopatch.runtime.builtin_patcher import BuiltinCwe89Patcher
from autopatch.runtime.builtin_scanner import BuiltinPythonScanner
from autopatch.runtime.patch_apply import SafePatchApplier
from autopatch.service.analysis import RuleBasedAnalyzer


def test_cwe89_patcher_creates_minimal_parameterized_diff(vulnerable_project: Path) -> None:
    finding = next(
        item for item in BuiltinPythonScanner().scan(vulnerable_project) if item.cwe == "CWE-89"
    )
    analysis = RuleBasedAnalyzer().analyze(vulnerable_project, finding)
    candidates = BuiltinCwe89Patcher().generate(vulnerable_project, finding, analysis)
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.changed_files == ["app.py"]
    assert candidate.changed_lines <= 5
    assert "id=%s" in candidate.unified_diff
    assert "cursor.execute(query, (user_id,))" in candidate.unified_diff

    SafePatchApplier().apply(vulnerable_project, candidate)
    patched = (vulnerable_project / "app.py").read_text(encoding="utf-8")
    assert 'f"SELECT * FROM users WHERE id={user_id}"' not in patched
    assert "cursor.execute(query, (user_id,))" in patched


def test_applier_rejects_stale_source_hash(vulnerable_project: Path) -> None:
    finding = next(
        item for item in BuiltinPythonScanner().scan(vulnerable_project) if item.cwe == "CWE-89"
    )
    analysis = RuleBasedAnalyzer().analyze(vulnerable_project, finding)
    candidate = BuiltinCwe89Patcher().generate(vulnerable_project, finding, analysis)[0]
    app = vulnerable_project / "app.py"
    app.write_text(app.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")

    try:
        SafePatchApplier().apply(vulnerable_project, candidate)
    except RuntimeError as exc:
        assert "original file changed" in str(exc)
    else:
        raise AssertionError("stale patch must be rejected")
