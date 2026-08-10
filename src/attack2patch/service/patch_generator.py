from dataclasses import dataclass
from difflib import unified_diff


@dataclass(frozen=True)
class GeneratedPatch:
    before: str
    after: str
    diff: str
    reason: str


def generate_parameterized_query_patch(source: str, file_path: str = "app.py") -> GeneratedPatch:
    """Handle only the explicitly supported demo query pattern."""
    vulnerable_query = 'query = f"SELECT id, name FROM users WHERE name = \'{name}\'"'
    safe_query = 'query = "SELECT id, name FROM users WHERE name = ?"'
    vulnerable_execute = "connection.execute(query).fetchall()"
    safe_execute = "connection.execute(query, (name,)).fetchall()"
    if source.count(vulnerable_query) != 1 or source.count(vulnerable_execute) != 1:
        raise ValueError("unsupported SQL query pattern")
    patched = source.replace(vulnerable_query, safe_query).replace(
        vulnerable_execute, safe_execute
    )
    diff = "".join(
        unified_diff(
            source.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
        )
    )
    return GeneratedPatch(
        before=source,
        after=patched,
        diff=diff,
        reason="Bind the untrusted name value as a SQLite parameter instead of interpolating it.",
    )
