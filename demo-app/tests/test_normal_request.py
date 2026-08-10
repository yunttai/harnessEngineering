import importlib.util
from pathlib import Path


def load_demo_app():
    path = Path(__file__).parents[1] / "app.py"
    spec = importlib.util.spec_from_file_location("demo_app", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    module.initialize_database()
    return module.app


def test_health():
    client = load_demo_app().test_client()
    assert client.get("/health").status_code == 200
