PYTHON ?= python3

.PHONY: run-dev lint test init-db run-discovery

run-dev:
	$(PYTHON) scripts/dev.py

lint:
	$(PYTHON) scripts/lint.py

test:
	PYTHONPATH=. $(PYTHON) -m unittest discover -s tests -p 'test_*.py'

init-db:
	PYTHONPATH=. $(PYTHON) scripts/init_db.py

run-discovery:
	PYTHONPATH=. $(PYTHON) scripts/run_discovery.py
