PYTHON ?= python3

.PHONY: run-dev lint test

run-dev:
	$(PYTHON) scripts/dev.py

lint:
	$(PYTHON) scripts/lint.py

test:
	PYTHONPATH=. $(PYTHON) -m unittest discover -s tests -p 'test_*.py'

