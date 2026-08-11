from app import FakeCursor, Request, get_user


def main() -> None:
    payload = "1 OR 1=1"
    cursor = FakeCursor()
    get_user(cursor, Request(args={"id": payload}))

    query, params = cursor.calls[0]
    assert payload not in query, "payload is still embedded in the SQL string"
    assert params == (payload,), "payload was not passed as a separate DB parameter"
    print("CWE-89 exploit mitigation confirmed")


if __name__ == "__main__":
    main()
