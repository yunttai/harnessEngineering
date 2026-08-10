from attack2patch.service.patch_generator import generate_parameterized_query_patch


def test_generates_complete_parameterized_query_patch():
    source = """\
query = f"SELECT id, name FROM users WHERE name = '{name}'"
rows = connection.execute(query).fetchall()
"""
    patch = generate_parameterized_query_patch(source)
    assert 'query = "SELECT id, name FROM users WHERE name = ?"' in patch.after
    assert "connection.execute(query, (name,)).fetchall()" in patch.after
    assert "--- a/app.py" in patch.diff
    assert "+++ b/app.py" in patch.diff


def test_rejects_unknown_query_shapes():
    try:
        generate_parameterized_query_patch("connection.execute(user_input)")
    except ValueError as exc:
        assert "unsupported" in str(exc)
    else:
        raise AssertionError("unsupported source must fail closed")
