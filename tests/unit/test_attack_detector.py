import json
from pathlib import Path

from attack2patch.service.attack_detector import detect_sql_injection


def test_detects_union_select():
    assert detect_sql_injection("x UNION SELECT password FROM users")


def test_allows_normal_name():
    assert detect_sql_injection("alice") == []


def test_detects_all_mvp_fixture_payloads():
    fixture = Path(__file__).parents[1] / "fixtures" / "attack-payloads.json"
    payloads = json.loads(fixture.read_text(encoding="utf-8"))
    assert all(detect_sql_injection(payload) for payload in payloads)


def test_does_not_flag_representative_normal_values():
    values = ["alice", "O'Reilly", "union station", "selective", "sleepy user", "1+1=2"]
    assert all(detect_sql_injection(value) == [] for value in values)
