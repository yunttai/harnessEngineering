from app import Request, create_database, get_user


def main() -> None:
    payload = "1 OR 1=1"
    with create_database() as connection:
        rows = get_user(connection, Request(args={"id": payload}))
    assert rows == [], f"SQL injection returned unauthorized rows: {rows!r}"
    print("CWE-89 exploit blocked by a real SQLite parameterized query")


if __name__ == "__main__":
    main()
