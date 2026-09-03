# Il Dottore developer task runner.
#
# These targets mirror the CI merge gate (.github/workflows/ci.yml) one-for-one, so
# `make ci` locally is the same wall you have to clear in the pipeline. Nothing here
# relaxes a threshold: a red gate is a red gate (docs/07 §3).
#
# Usage:
#   make            # = make gates (the full local merge gate)
#   make test       # fast: unit + property + everything, quiet
#   make fix        # autofix what is autofixable (ruff format + ruff --fix)

PY ?= .venv/bin/python
BIN ?= .venv/bin
SRC := src
TESTS := tests

.DEFAULT_GOAL := gates
.PHONY: help venv install lint format-check format fix type imports spec-lint \
        test cov selfscan bandit audit static gates ci schema clean

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[1m%-14s\033[0m %s\n",$$1,$$2}'

venv: ## Create the virtualenv
	python3 -m venv .venv

install: ## Editable install with dev extras
	$(PY) -m pip install -e ".[dev]"

# --- static job (lint · format · types · boundaries) --------------------------------

lint: ## Ruff lint (src + tests)
	$(BIN)/ruff check $(SRC) $(TESTS)

format-check: ## Ruff format check (fails if reformatting is needed)
	$(BIN)/ruff format --check $(SRC) $(TESTS)

format: ## Ruff format in place
	$(BIN)/ruff format $(SRC) $(TESTS)

fix: format ## Autofix: ruff format + ruff --fix
	$(BIN)/ruff check --fix $(SRC) $(TESTS)

type: ## mypy (strict)
	$(BIN)/mypy $(SRC)

imports: ## Import-boundary contract (import-linter)
	$(BIN)/lint-imports

static: lint format-check type imports ## The full CI `static` job

# --- validate job (detection gates) -------------------------------------------------

spec-lint: ## Gate 1: schema + policy + fixtures-prove-detection lint
	$(BIN)/dottore lint specs/

test: ## Full test suite, quiet
	$(BIN)/pytest -q

cov: ## Coverage gate: core >= 85% (CI gate 12)
	$(BIN)/pytest -q --cov=$(SRC)/ildottore --cov-report=term-missing --cov-fail-under=85

selfscan: ## Gate 11: self-scan our own judge; fail on new high/critical
	$(PY) -m tests.selfscan.run --out reports/self-scan.sarif.json

# --- supply chain (advisory, not in the fast static job) ----------------------------

bandit: ## Security linter (no medium/high expected)
	$(BIN)/bandit -q -r $(SRC)

audit: ## Dependency vulnerability audit
	$(BIN)/pip-audit

# --- aggregate ----------------------------------------------------------------------

gates: static spec-lint cov selfscan bandit audit ## The full local merge gate
	@echo "All gates green."

ci: gates ## Alias for the full gate set (what the pipeline runs)

schema: ## Export the generated JSON schemas to stdout
	$(BIN)/dottore schema export

clean: ## Remove caches, coverage and generated runtime artifacts
	rm -rf .pytest_cache .mypy_cache .ruff_cache reports .dottore htmlcov .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
