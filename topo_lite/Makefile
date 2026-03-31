PYTHON ?= python3

.PHONY: run-dev run-web-stack lint test init-db backup-state restore-state run-discovery run-scheduler run-probe run-deep-probe run-probe-scheduler run-classification run-diff

run-dev:
	$(PYTHON) scripts/dev.py

run-web-stack:
	PYTHONPATH=. $(PYTHON) scripts/run_web_stack.py

lint:
	$(PYTHON) scripts/lint.py

test:
	PYTHONPATH=. $(PYTHON) -m unittest discover -s tests -p 'test_*.py'

init-db:
	PYTHONPATH=. $(PYTHON) scripts/init_db.py

backup-state:
	PYTHONPATH=. $(PYTHON) scripts/backup_state.py

restore-state:
	PYTHONPATH=. $(PYTHON) scripts/restore_state.py

run-discovery:
	PYTHONPATH=. $(PYTHON) scripts/run_discovery.py

run-scheduler:
	PYTHONPATH=. $(PYTHON) scripts/run_scheduler.py

run-probe:
	PYTHONPATH=. $(PYTHON) scripts/run_probe.py

run-deep-probe:
	PYTHONPATH=. $(PYTHON) scripts/run_deep_probe.py

run-probe-scheduler:
	PYTHONPATH=. $(PYTHON) scripts/run_probe_scheduler.py

run-classification:
	PYTHONPATH=. $(PYTHON) scripts/run_classification.py

run-diff:
	PYTHONPATH=. $(PYTHON) scripts/run_diff.py
