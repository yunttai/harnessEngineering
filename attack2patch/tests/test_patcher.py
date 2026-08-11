from __future__ import annotations

from pathlib import Path

from autopatch.runtime.builtin_patcher import BuiltinCwe89Patcher
from autopatch.runtime.builtin_scanner import BuiltinPythonScanner
from autopatch.runtime.builtin_security_patchers import (
    BuiltinCwe22FlaskPatcher,
    BuiltinCwe78Patcher,
    BuiltinCwe502YamlPatcher,
)
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
    assert "id=?" in candidate.unified_diff
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


def _finding(project: Path, cwe: str):
    finding = next(item for item in BuiltinPythonScanner().scan(project) if item.cwe == cwe)
    return finding, RuleBasedAnalyzer().analyze(project, finding)


def test_cwe78_patcher_converts_shell_fstring_to_fixed_argv(tmp_path: Path) -> None:
    source = tmp_path / "command.py"
    source.write_text(
        '''import subprocess

def ping(host):
    return subprocess.run(f"ping -c 1 {host}", shell=True, timeout=2)
''',
        encoding="utf-8",
    )
    finding, analysis = _finding(tmp_path, "CWE-78")
    candidate = BuiltinCwe78Patcher().generate(tmp_path, finding, analysis)[0]

    SafePatchApplier().apply(tmp_path, candidate)
    patched = source.read_text(encoding="utf-8")
    assert "shell=True" not in patched
    assert "['ping', '-c', '1', host]" in patched
    assert not [item for item in BuiltinPythonScanner().scan(tmp_path) if item.cwe == "CWE-78"]


def test_cwe78_patcher_rejects_dynamic_value_embedded_in_one_argument(tmp_path: Path) -> None:
    (tmp_path / "command.py").write_text(
        '''import subprocess

def lookup(host):
    return subprocess.run(f"ping {host}.example", shell=True)
''',
        encoding="utf-8",
    )
    finding, analysis = _finding(tmp_path, "CWE-78")
    assert BuiltinCwe78Patcher().generate(tmp_path, finding, analysis) == []


def test_cwe502_patcher_replaces_unsafe_yaml_loader(tmp_path: Path) -> None:
    source = tmp_path / "payload.py"
    source.write_text(
        '''import yaml

def parse(payload):
    return yaml.load(payload, Loader=yaml.UnsafeLoader)
''',
        encoding="utf-8",
    )
    finding, analysis = _finding(tmp_path, "CWE-502")
    candidate = BuiltinCwe502YamlPatcher().generate(tmp_path, finding, analysis)[0]

    SafePatchApplier().apply(tmp_path, candidate)
    patched = source.read_text(encoding="utf-8")
    assert "yaml.safe_load(payload)" in patched
    assert "UnsafeLoader" not in patched
    assert not [item for item in BuiltinPythonScanner().scan(tmp_path) if item.cwe == "CWE-502"]


def test_cwe22_patcher_uses_flask_safe_directory_api(tmp_path: Path) -> None:
    source = tmp_path / "download.py"
    source.write_text(
        '''import flask
import os

DOWNLOAD_ROOT = "/srv/downloads"

def download():
    filename = flask.request.args["file"]
    return flask.send_file(os.path.join(DOWNLOAD_ROOT, filename), as_attachment=True)
''',
        encoding="utf-8",
    )
    finding, analysis = _finding(tmp_path, "CWE-22")
    candidate = BuiltinCwe22FlaskPatcher().generate(tmp_path, finding, analysis)[0]

    SafePatchApplier().apply(tmp_path, candidate)
    patched = source.read_text(encoding="utf-8")
    assert "flask.send_from_directory(DOWNLOAD_ROOT, filename, as_attachment=True)" in patched
    assert "os.path.join" not in patched
    assert not [item for item in BuiltinPythonScanner().scan(tmp_path) if item.cwe == "CWE-22"]


def test_cwe22_patcher_rejects_attacker_controlled_directory_root(tmp_path: Path) -> None:
    (tmp_path / "download.py").write_text(
        '''import flask
import os

def download():
    root = flask.request.args["root"]
    filename = flask.request.args["file"]
    return flask.send_file(os.path.join(root, filename))
''',
        encoding="utf-8",
    )
    finding, analysis = _finding(tmp_path, "CWE-22")
    assert finding.metadata["root_trusted"] is False
    assert BuiltinCwe22FlaskPatcher().generate(tmp_path, finding, analysis) == []
