import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)
DATABASE = "/tmp/demo.db"


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


if __name__ == "__main__":
    initialize_database()
    app.run(host="0.0.0.0", port=5000)
