from __future__ import annotations

import json
import sqlite3
import sys
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit


@dataclass
class Request:
    args: dict[str, str]


def create_database() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
        INSERT INTO users (id, name) VALUES (1, 'demo'), (2, 'admin');
        """
    )
    return connection


def get_user(connection: sqlite3.Connection, request: Request) -> list[dict[str, object]]:
    cursor = connection.cursor()
    user_id = request.args.get("id", "")
    query = f"SELECT * FROM users WHERE id={user_id}"  # noqa: S608 - vulnerable fixture
    cursor.execute(query)
    return [dict(row) for row in cursor.fetchall()]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/health":
            self._json(200, {"status": "ok"})
            return
        if parsed.path != "/users":
            self._json(404, {"error": "not found"})
            return
        request = Request(
            args={key: values[0] for key, values in parse_qs(parsed.query).items()}
        )
        try:
            with create_database() as connection:
                rows = get_user(connection, request)
            self._json(200, {"count": len(rows), "rows": rows})
        except sqlite3.Error as exc:
            self._json(400, {"error": type(exc).__name__})

    def _json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def serve() -> None:
    HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()  # noqa: S104 - container bind


if __name__ == "__main__" and "--serve" in sys.argv:
    serve()
