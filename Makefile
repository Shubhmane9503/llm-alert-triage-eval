PYTHON ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

.PHONY: setup data labels baseline test eval injection report lint typecheck clean

setup:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install --upgrade pip
	$(BIN)/python -m pip install -e '.[dev]'

data:
	$(BIN)/triage-eval data --output data

labels:
	$(BIN)/triage-eval ingest --config configs/dev.yaml
	$(BIN)/triage-eval label --config configs/dev.yaml

baseline:
	$(BIN)/triage-eval baseline --config configs/dev.yaml

test:
	$(BIN)/pytest

lint:
	$(BIN)/ruff check src tests scripts

typecheck:
	$(BIN)/mypy src/triage_eval

eval:
	$(BIN)/triage-eval run --config configs/heldout.yaml --runs 3

injection:
	$(BIN)/triage-eval inject --config configs/heldout.yaml

report:
	$(BIN)/triage-eval report --results results

clean:
	rm -rf $(VENV) .pytest_cache .mypy_cache .ruff_cache
