from app import FakeCursor, Request, get_user


def test_get_user_returns_row() -> None:
    cursor = FakeCursor()
    result = get_user(cursor, Request(args={"id": "1"}))

    assert result == {"id": "1", "name": "demo"}
    assert len(cursor.calls) == 1
