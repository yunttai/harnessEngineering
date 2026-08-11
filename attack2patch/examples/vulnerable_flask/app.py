from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class Request:
    args: dict[str, str]


class FakeCursor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...] | None]] = []

    def execute(self, query: str, params: tuple[Any, ...] | None = None) -> None:
        self.calls.append((query, params))

    def fetchone(self) -> dict[str, str]:
        return {"id": "1", "name": "demo"}


def get_user(cursor: FakeCursor, request: Request) -> dict[str, str]:
    user_id = request.args.get("id", "")
    query = f"SELECT * FROM users WHERE id={user_id}"
    cursor.execute(query)
    return cursor.fetchone()
