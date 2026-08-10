import pytest

from test_normal_request import load_demo_app


@pytest.mark.baseline_vulnerable
def test_baseline_sql_injection_is_reproducible():
    """The isolated baseline must stay vulnerable so the demo has a real before state."""
    client = load_demo_app().test_client()
    response = client.get("/api/users", query_string={"name": "' OR 1=1--"})
    assert response.status_code == 200
    assert response.get_json() == [{"id": 1, "name": "alice"}, {"id": 2, "name": "bob"}]
