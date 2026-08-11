.PHONY: install check test demo scan api schemas

install:
	python -m pip install -e ".[dev]"

check:
	bash scripts/check.sh

test:
	pytest -q

demo:
	bash scripts/demo.sh

scan:
	attack2patch scan examples/vulnerable_flask

api:
	attack2patch serve --host 127.0.0.1 --port 8000

schemas:
	PYTHONPATH=src python scripts/generate-schemas.py
