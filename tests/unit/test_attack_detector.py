from attack2patch.service.attack_detector import detect_sql_injection


def test_detects_union_select():
    assert detect_sql_injection("x UNION SELECT password FROM users")


def test_allows_normal_name():
    assert detect_sql_injection("alice") == []
