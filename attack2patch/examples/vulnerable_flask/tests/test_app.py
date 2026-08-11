import unittest

from app import Request, create_database, get_user


class GetUserTests(unittest.TestCase):
    def test_get_user_returns_row(self) -> None:
        with create_database() as connection:
            result = get_user(connection, Request(args={"id": "1"}))

        self.assertEqual(result, [{"id": 1, "name": "demo"}])


if __name__ == "__main__":
    unittest.main()
