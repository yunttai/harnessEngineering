import json
import os
import re
import sqlite3
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request

app = Flask(__name__)
DATABASE = str(Path(tempfile.gettempdir()) / "attack2patch-demo.db")
ACCESS_LOG_PATH = os.getenv("DEMO_ACCESS_LOG_PATH")
SENSITIVE_KEY = re.compile(
    r"(?i)(authorization|cookie|token|password|passwd|secret|api[_-]?key)"
)
LOG_LOCK = threading.Lock()


def initialize_database() -> None:
    with sqlite3.connect(DATABASE) as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)")
        connection.execute("DELETE FROM users")
        connection.executemany("INSERT INTO users(name) VALUES (?)", [("alice",), ("bob",)])


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/api/users")
def get_users():
    name = request.args.get("name", "")
    # INTENTIONALLY VULNERABLE: isolated demo target for Attack2Patch only.
    query = f"SELECT id, name FROM users WHERE name = '{name}'"
    with sqlite3.connect(DATABASE) as connection:
        rows = connection.execute(query).fetchall()
    return jsonify([{"id": row[0], "name": row[1]} for row in rows])


@app.after_request
def write_access_log(response):
    if not ACCESS_LOG_PATH:
        return response
    parameters = {
        key: "***REDACTED***" if SENSITIVE_KEY.search(key) else value
        for key, value in request.args.items()
    }
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "method": request.method,
        "path": request.path,
        "parameters": parameters,
        "source_ip": request.remote_addr or "0.0.0.0",
        "status_code": response.status_code,
        "headers": {},
    }
    path = Path(ACCESS_LOG_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    with LOG_LOCK, path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        stream.flush()
    return response


if __name__ == "__main__":
    initialize_database()
    app.run(host="0.0.0.0", port=5000)
