from dataclasses import dataclass


@dataclass(frozen=True)
class GeneratedPatch:
    before: str
    after: str


def generate_parameterized_query_patch(source: str) -> GeneratedPatch:
    """Handle only the explicitly supported demo query pattern."""
    vulnerable_query = 'query = f"SELECT id, name FROM users WHERE name = \'{name}\'"'
    safe_query = 'query = "SELECT id, name FROM users WHERE name = ?"'
    vulnerable_execute = "connection.execute(query).fetchall()"
    safe_execute = "connection.execute(query, (name,)).fetchall()"
    if vulnerable_query not in source or vulnerable_execute not in source:
        raise ValueError("unsupported SQL query pattern")
    patched = source.replace(vulnerable_query, safe_query).replace(
        vulnerable_execute, safe_execute
    )
    return GeneratedPatch(before=source, after=patched)
