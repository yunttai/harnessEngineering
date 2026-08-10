from attack2patch.service.patch_generator import generate_parameterized_query_patch


def test_generates_complete_parameterized_query_patch():
    source = """\
query = f"SELECT id, name FROM users WHERE name = '{name}'"
rows = connection.execute(query).fetchall()
"""
    patch = generate_parameterized_query_patch(source)
    assert 'query = "SELECT id, name FROM users WHERE name = ?"' in patch.after
    assert "connection.execute(query, (name,)).fetchall()" in patch.after
