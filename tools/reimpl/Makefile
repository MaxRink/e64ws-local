PYTHON ?= python3
STATE  ?= /tmp/e64ctl

.PHONY: test run run-dev scenario clean

test:
	cd tests && $(PYTHON) -m unittest discover -s . -p "test_*.py"

run:
	PYTHONPATH=src $(PYTHON) -m e64ctl --state-dir $(STATE)

run-dev:
	PYTHONPATH=src $(PYTHON) -m e64ctl --state-dir $(STATE) --dev-mode

scenario:
	PYTHONPATH=src $(PYTHON) tools/scenario.py \
		--scenario /tmp/equiv/scenarios/02_readonly.json \
		--out runs/reimpl/02_readonly.jsonl --state-dir $(STATE)

clean:
	rm -rf runs __pycache__ src/e64ctl/__pycache__ tests/__pycache__
